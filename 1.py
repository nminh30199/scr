import subprocess
import time
import shutil
import os
import select
import fcntl

ports = list(range(1001, 1011)) + list(range(10001, 10011)) + list(range(4000, 4011))
total_ports = len(ports)

input_file = "vt.txt"
output_tmp = "output.txt"
output_save = "vn.txt"

if os.path.exists(output_save):
    os.remove(output_save)

def set_nonblocking(fd):
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

def monitor_zmap_output(zmap_proc, keyword="zmap_completed"):
    stderr_fd = zmap_proc.stderr.fileno()
    set_nonblocking(stderr_fd)
    
    while zmap_proc.poll() is None:
        ready, _, _ = select.select([stderr_fd], [], [], 0.1)
        if ready:
            data = os.read(stderr_fd, 1024)
            if data:
                line = data.decode('utf-8', errors='ignore').strip()
                if keyword.lower() in line.lower():
                    return True
        time.sleep(0.01)
    return False

for i, port in enumerate(ports, start=1):
    remaining = total_ports - i
    print(f"🔍 Scanning port: {port} ({i}/{total_ports}) - Còn {remaining} ports nữa sẽ done!")
    
    start_time = time.time()

    zmap_cmd = [
        "zmap",
        "-p", str(port),
        "-w", input_file,
        "--rate=10000000000000000",
        "--cooldown-time=10",
        "--probe-module=tcp_synscan",
        "--max-sendto-failures=100000"
    ]
    prox_cmd = ["./prox", "-p", str(port)]

    zmap_proc = subprocess.Popen(
        zmap_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=0
    )
    
    with open(output_tmp, "w", buffering=1) as outfile:
        prox_proc = subprocess.Popen(
            prox_cmd,
            stdin=zmap_proc.stdout,
            stdout=outfile,
            bufsize=0
        )
        zmap_proc.stdout.close()

        if monitor_zmap_output(zmap_proc, "zmap_completed"):
            print(f"✅ ZMap completed scanning port {port}")
        else:
            print(f"⚠️ ZMap terminated early for port {port}")

        if zmap_proc.poll() is None:
            zmap_proc.terminate()
        if prox_proc.poll() is None:
            prox_proc.terminate()

        try:
            zmap_proc.wait(timeout=3)
            prox_proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            zmap_proc.kill()
            prox_proc.kill()
            print(f"⚠️ Forcefully killed processes for port {port}")

    num_proxies = 0
    if os.path.exists(output_tmp):
        with open(output_tmp, "r") as src:
            with open(output_save, "a") as dst:
                shutil.copyfileobj(src, dst)
            num_proxies = sum(1 for _ in open(output_tmp))
        os.remove(output_tmp)
        duration = time.time() - start_time
        print(f"✅ Saved {num_proxies} proxies from port {port} to {output_save} with {int(duration)}s")
    else:
        print(f"⚠️ No {output_tmp} found after scanning port {port}")

if os.path.exists(output_save):
    print("🔄 Removing duplicate proxies in vn.txt...")
    temp_unique = output_save + ".unique.tmp"
    
    cmd = f"sort -u {output_save} > {temp_unique}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        os.replace(temp_unique, output_save)
        num_unique = int(subprocess.check_output(f"wc -l < {output_save}", shell=True).decode().strip())
        print(f"✅ Filtered {num_unique} unique proxies into {output_save}")
    else:
        print(f"⚠️ Failed to filter duplicates: {result.stderr}")
        if os.path.exists(temp_unique):
            os.remove(temp_unique)
else:
    print(f"⚠️ No {output_save} found for duplicate filtering")

print("✅ Completed scanning all ports and filtering duplicates.")