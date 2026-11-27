// paileactivist.github.io/toolz/adblock.html (d3ward toolz). On window.onload every host is fetched
// (HEAD,no-cors, 8s abort); failure = blocked (host div turns var(--green)), response = red. Completion:
// fetchTests() resolved -> .loadingWrap faded out and body loses _overflowhidden. The optional OEM section is
// excluded from the page's own points and from this score.
async () => {
  await waitFor(() => !document.body.classList.contains('_overflowhidden') && document.querySelectorAll('#test > div').length > 0, 120000, 'toolz completion');
  const tests = [];
  document.querySelectorAll('#test > div').forEach((cat) => {
    if (cat.id === 'OEM') return;
    cat.querySelectorAll('.test').forEach((grp) => {
      grp.querySelectorAll(':scope > div > div').forEach((h) => {
        tests.push({ category: cat.id, name: grp.id + ' / ' + txt(h), pass: /green/.test(h.style.background) });
      });
    });
  });
  return build(tests, { note: 'OEM section excluded (matches the page score)' });
}
