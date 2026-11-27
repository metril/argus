// superadblocktest.com (adblock.js). Loaded with ?run=1 so the test auto-starts. Rows .adblockHostDiv carry
// data-status (blocked|accessible|...), data-category, data-group. Completion: body.test-complete.
async () => {
  await waitFor(() => document.body.classList.contains('test-complete') && document.querySelectorAll('.adblockHostDiv').length > 0, 900000, 'superadblocktest completion');
  const tests = [...document.querySelectorAll('.adblockHostDiv')].map((r) => ({
    category: r.dataset.category || 'Uncategorised',
    name: (r.dataset.group ? r.dataset.group + ' / ' : '') + (r.dataset.label || txt(r)),
    pass: r.dataset.status === 'blocked',
  }));
  return build(tests, { reportedScore: txt(document.getElementById('percentage')) });
}
