const Wappalyzer = require('wappalyzer');
const options = {
  debug: false,
  delay: 0,
  maxWait: 5000,
  probe: false,
  noScripts: false,
};
const wappalyzer = new Wappalyzer(options);
async function run() {
  await wappalyzer.init();
  console.time('wapp');
  try {
    const site = await wappalyzer.open('https://ymautomation.com');
    const results = await site.analyze();
    console.log(results.technologies.map(t => t.name).join(', '));
  } catch (e) {
    console.error(e.message);
  }
  console.timeEnd('wapp');
  await wappalyzer.destroy();
}
run();
