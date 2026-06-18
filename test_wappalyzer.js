const Wappalyzer = require('wappalyzer');

const url = process.argv[2] || 'https://vgmgastrocentre.com';

const options = {
  debug: false,
  delay: 500,
  headers: {},
  maxDepth: 1,
  maxUrls: 1,
  maxWait: 5000,
  recursive: false,
  probe: true,
  userAgent: 'Wappalyzer',
  htmlMaxCols: 2000,
  htmlMaxRows: 2000,
  noScripts: false,
};

const wappalyzer = new Wappalyzer(options);

(async function() {
  try {
    await wappalyzer.init();
    const site = await wappalyzer.open(url);
    const results = await site.analyze();
    console.log(JSON.stringify(results, null, 2));
  } catch (error) {
    console.error('Error:', error.message || error);
  } finally {
    await wappalyzer.destroy();
  }
})();
