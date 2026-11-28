// Dev-only Playwright driver (run with the harness server up): screenshots every state and runs the layout/contrast checks.
// Usage in the Playwright MCP: browser_run_code_unsafe with filename = this file. Returns the violations (empty object = zero).
async (page) => {
  const OUT = '/tmp/claude-751001104/-home-OLYMPOS-jagannath-projects-adblocker/6afcd87f-eda8-4123-98a1-8a30069e2d13/scratchpad/k1b-shots/';
  const B = 'http://127.0.0.1:5199/';
  const WIDTHS = [1280, 400, 1600], THEMES = ['light', 'dark'];
  const report = {};
  const sleep = (ms) => page.waitForTimeout(ms);
  async function open(url, w) {
    await page.setViewportSize({ width: w, height: 800 });
    await page.goto(B + url);
    await page.waitForFunction(() => window.__ready && document.querySelector('.cm,.pop'));
    await sleep(300);
  }
  async function shot(tag, name, kind) {
    await sleep(120);
    await page.screenshot({ path: OUT + tag + '-' + name + '.png' });
    const r = await page.evaluate((k) => window.CK.run(k), kind || 'page');
    const bad = Object.entries(r).filter(([, v]) => v.length);
    if (bad.length) report[tag + '-' + name] = Object.fromEntries(bad);
  }
  const click = async (sel, o) => { try { await page.locator(sel).first().click({ timeout: 4000, ...(o || {}) }); } catch (e) { throw new Error('click ' + sel + ': ' + String(e.message).split('\n').slice(0, 6).join(' | ')); } await sleep(120); };
  for (const w of WIDTHS) for (const theme of THEMES) {
    const tag = w + '-' + theme;
    try {
      await open('cookies.html?theme=' + theme + '&prov=on', w);
      await shot(tag, '01-cookies');
      const top0 = await page.evaluate(() => document.querySelector('table.ck').getBoundingClientRect().top);
      await click('button[aria-label="Select _ga"]');
      const top1 = await page.evaluate(() => document.querySelector('table.ck').getBoundingClientRect().top);
      if (Math.abs(top0 - top1) > 0.5) report[tag + '-selection-shift'] = [top0, top1];
      await shot(tag, '02-selected');
      await click('[data-testid=bulk-delete]');
      await shot(tag, '03-bulk-armed');
      await page.keyboard.press('Escape');
      await click('text=Clear selection');
      await click('.lnk:text-is("_ga")');
      await sleep(200);
      await shot(tag, '04-drawer');
      await click('#blockck');
      await page.evaluate(() => document.querySelector('.dwr').scrollTo(0, 9999));
      await shot(tag, '05-drawer-block');
      await click('[data-testid=drawer-delete]');
      await shot(tag, '06-drawer-armed');
      await page.keyboard.press('Escape');
      await page.keyboard.press('Escape');
      await click('button:text-is("Stripped by Argus")');
      await shot(tag, '07-stripped');
      await click('.lnk:text-is("_gid")');
      await sleep(200);
      await shot(tag, '08-drawer-stripped');
      await page.keyboard.press('Escape');
      await click('button:text-is("Stripped by Argus")');
      await click('button:text-is("Export")');
      await sleep(200);
      await shot(tag, '09-export');
      await page.keyboard.press('Escape');
      await click('button:text-is("Import")');
      await page.fill('#imt', '# Netscape HTTP Cookie File\n.stackoverflow.com\tTRUE\t/\tTRUE\t1798761600\tpreferred_lang\ten\nstackoverflow.com\tFALSE\t/\tTRUE\t0\tprefs\ttheme%3Ddark\n.stackoverflow.com\tTRUE\t/\tFALSE\t1798761600\t__Secure-flag\t1');
      await sleep(600);
      await shot(tag, '10-import');
      await page.keyboard.press('Escape');
      await click('button:text-is("Add cookie")');
      await sleep(150);
      await page.fill('#dn', '__Host-x');
      await click('#dho');
      await sleep(400);
      await shot(tag, '11-add-invalid');
      await page.keyboard.press('Escape');
      await shot(tag, '11b-add-discard');
      await page.keyboard.press('Escape');
      await click('[role=tab]:text-is("Snapshots")');
      await page.fill('input[aria-label="Snapshot name"]', 'work account');
      await click('button:text-is("Save current")');
      await sleep(200);
      await page.fill('input[aria-label="Snapshot name"]', 'personal');
      await click('button:text-is("Save current")');
      await sleep(500);
      await shot(tag, '12-snapshots');
      await click('table.sn .cfb');
      await sleep(400);
      await shot(tag, '13-snapshot-armed');
      await page.keyboard.press('Escape');
      await click('table.sn tbody tr:first-child .cfm.l .cfb');
      await sleep(200);
      await shot(tag, '13b-snapshot-delete-armed');
      await page.keyboard.press('Escape');
      await click('[role=tab]:text-is("Activity")');
      await sleep(300);
      await shot(tag, '14-activity');
      await click('[role=tab]:text-is("Rules")');
      await sleep(200);
      const add = async (card, label, v, field) => { await page.fill(`input[aria-label="${label}"]`, v); await click(`.card:has(h3:text-is("${card}")) button:text-is("Add")`); await sleep(150); };
      await add('Keep list', 'Site to keep', 'stackoverflow.com');
      await add('Keep list', 'Site to keep', 'news.example.org');
      await add('Greylist', 'Site to greylist', 'video.example.net');
      await page.fill('input[aria-label="Domain"]', 'stackoverflow.com');
      await page.fill('input[aria-label="Cookie name"]', '__Host-sosid');
      await click('.card:has(h3:text-is("Protected cookies")) button:text-is("Add")');
      await sleep(300);
      await shot(tag, '15-rules');
      await click('.lst .cfb');
      await shot(tag, '16-rules-armed');
      await page.keyboard.press('Escape');
      await open('cookies.html?theme=' + theme + '&prov=off', w);
      await shot(tag, '17-cookies-prov-off');
      await click('.lnk:text-is("_ga")');
      await sleep(200);
      await shot(tag, '18-drawer-prov-off');
      await open('cookies.html?theme=' + theme + '&prov=on&n=5000', w);
      await click('[role=radio]:text-is("All sites")');
      await sleep(500);
      await shot(tag, '21-large-all');
      await page.evaluate(() => { const t = document.querySelector('.cm .tw'); if (t) t.scrollTop = 40000; window.scrollTo(0, 40000); });
      await sleep(400);
      await shot(tag, '22-large-scrolled');
      await open('popup.html?theme=' + theme, w);
      await shot(tag, '19-popup-actions', 'popup');
      await open('popup.html?theme=' + theme + '&view=stats', w);
      await sleep(400);
      await shot(tag, '20-popup-stats', 'popup');
    } catch (e) {
      report[tag + '-ERROR'] = String(e.message).split('\n')[0];
    }
  }
  return report;
}
