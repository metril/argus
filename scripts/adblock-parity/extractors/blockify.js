// getblockify.com/adblock-test (Next.js). Click Deep + "Start Ad-Blocker Test"; completion: the
// "Category Breakdown" heading appears. Results: "Ads That Got Through" (fail) and "Successfully Blocked"
// (pass) collapsibles, each grouped by category with publisher names.
async () => {
  const byText = (sel, re) => [...document.querySelectorAll(sel)].find((e) => re.test(txt(e)));
  await waitFor(() => byText('button', /Start Ad-Blocker Test/) || byText('h3', /Category Breakdown/), 60000, 'blockify start button');
  // Clicks before React hydrates are lost (the depth would stay at the default): wait for event props.
  await waitFor(() => Object.keys(byText('button', /Start Ad-Blocker Test/)).some((k) => k.startsWith('__reactProps')), 60000, 'blockify hydration');
  if (!byText('h3', /Category Breakdown/)) {
    const deep = [...document.querySelectorAll('button,[role=radio],label,div,span')].find((e) => e.children.length === 0 && txt(e) === 'Deep');
    if (!deep) throw new Error('Deep test depth control not found');
    (deep.closest('button,[role=radio],label') || deep).click();
    byText('button', /Start Ad-Blocker Test/).click();
  }
  await waitFor(() => byText('h3', /Category Breakdown/) && byText('button', /Successfully Blocked/), 300000, 'blockify result');
  const open = (re) => {
    const b = byText('button', re);
    if (b && !b.nextElementSibling) b.click();
    return b;
  };
  open(/Ads That Got Through/); open(/Successfully Blocked/);
  await waitFor(() => { const b = byText('button', /Successfully Blocked/); return b && b.nextElementSibling; }, 10000, 'blocked list expand');
  const tests = [];
  const collect = (re, pass) => {
    const b = byText('button', re);
    if (!b || !b.nextElementSibling) return;
    b.nextElementSibling.querySelectorAll(':scope > div').forEach((g) => {
      const label = g.querySelector('.uppercase');
      if (!label) return;
      g.querySelectorAll('span.text-sm').forEach((s) => tests.push({ category: txt(label), name: txt(s).replace(/,$/, ''), pass }));
    });
  };
  collect(/Ads That Got Through/, false);
  collect(/Successfully Blocked/, true);
  return build(tests, { reportedText: txt(document.querySelector('main')).slice(0, 400) });
}
