// adblock-tester.com (svelte app). Each service has checks with <b.status data-status=...>:
// pending|unknown|blocked|likelyBlocked|likelyUnblocked|unblocked. Completion: .final-score-text present and no
// pending status, stable for 1.5s. Pass = blocked or likelyBlocked.
async () => {
  await waitStable(() => document.querySelector('.final-score-text') && document.querySelectorAll('[data-status="pending"]').length === 0 && document.querySelectorAll('[data-status]').length > 0, 240000, 1500, 'adblock-tester final score');
  const tests = [];
  document.querySelectorAll('.block.section').forEach((sec) => {
    const category = txt(sec.querySelector('h2'));
    sec.querySelectorAll('.block.service').forEach((svc) => {
      const svcName = txt(svc.querySelector('h4'));
      svc.querySelectorAll('ol.check-list > li').forEach((li) => {
        const st = li.querySelector('[data-status]');
        if (!st) return;
        tests.push({ category, name: svcName + ' / ' + txt(li.querySelector('.name')).replace(/:$/, ''), pass: /^(blocked|likelyBlocked)$/.test(st.dataset.status), status: st.dataset.status });
      });
    });
  });
  return build(tests, { reportedScore: txt(document.querySelector('.final-score-text')) });
}
