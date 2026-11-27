// adblock.turtlecute.org (js/index.js). The test self-starts on idle. Per host: fetch(HEAD,no-cors) with 8s
// abort; a rejection or abort = blocked (green svg), a response = not blocked (red svg). Plus 2 cosmetic and
// 2 script probes (classes _bg-green/_bg-red). Completion: #adb_test_r is filled with "Total/blocked/not blocked".
async () => {
  await waitFor(() => /\d+\s*blocked/.test(txt(document.querySelector('#adb_test_r'))) && !document.querySelector('#share_result').disabled, 180000, 'turtlecute result');
  const tests = [];
  const probe = (id, category, name) => { const e = document.getElementById(id); tests.push({ category, name, pass: !!e && e.classList.contains('_bg-green') }); };
  probe('ct_static', 'Cosmetic Filter', 'Static Ad');
  probe('ct_dynamic', 'Cosmetic Filter', 'Dynamic Ad');
  probe('sfa_1', 'Ad Scripts', 'ads.js');
  probe('sfa_2', 'Ad Scripts', 'pagead.js');
  document.querySelectorAll('#test > div.grid').forEach((cat) => {
    cat.querySelectorAll('.test').forEach((grp) => {
      grp.querySelectorAll(':scope > div > div').forEach((h) => {
        tests.push({ category: cat.id, name: grp.id + ' / ' + txt(h), pass: h.innerHTML.includes('var(--green)') });
      });
    });
  });
  return build(tests, { reported: txt(document.querySelector('#adb_test_r')) });
}
