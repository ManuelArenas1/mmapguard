const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

const DIR = __dirname;
const scenes = JSON.parse(fs.readFileSync(path.join(DIR, 'scenes.json'), 'utf8'));
const template = fs.readFileSync(path.join(DIR, 'template.html'), 'utf8');

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1280, height: 720 } });
  for (const sc of scenes) {
    const html = template.replace('__SLOT__', sc.html);
    const tmp = path.join(DIR, 'slides', sc.id + '.html');
    fs.writeFileSync(tmp, html);
    await page.goto('file://' + tmp);
    await page.screenshot({ path: path.join(DIR, 'slides', sc.id + '.png') });
    console.log('rendered', sc.id);
  }
  await browser.close();
})();
