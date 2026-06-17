const fs = require('fs');
const Wappalyzer = require('wappalyzer');

const args = process.argv.slice(2);
if (args.length === 0) {
    console.error("Usage: node wappalyzer_runner.js <urls.txt>");
    process.exit(1);
}

const file = args[0];
const urls = fs.readFileSync(file, 'utf8').split('\n').filter(l => l.trim() !== '');

const options = {
  debug: false,
  delay: 0,
  headers: {},
  maxDepth: 1,
  maxUrls: 1,
  maxWait: 5000,
  recursive: false,
  probe: false,
  userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
  htmlMaxCols: 2000,
  htmlMaxRows: 2000,
  noScripts: false,
};

const wappalyzer = new Wappalyzer(options);

async function run() {
    await wappalyzer.init();
    
    const resultsMap = {};
    const concurrency = 15;
    
    for (let i = 0; i < urls.length; i += concurrency) {
        const chunk = urls.slice(i, i + concurrency);
        
        await Promise.all(chunk.map(async (url) => {
            let finalUrl = url;
            if (!finalUrl.startsWith('http')) {
                finalUrl = 'https://' + finalUrl;
            }
            
            try {
                const site = await wappalyzer.open(finalUrl);
                const results = await site.analyze();
                resultsMap[url] = results;
            } catch (error) {
                resultsMap[url] = { error: error.message || String(error) };
            }
        }));
    }
    
    await wappalyzer.destroy();
    
    console.log(JSON.stringify(resultsMap, null, 2));
}

run();
