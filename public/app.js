(function () {
  // Filteren van tabellen op tekst en op scope/uitkomst
  var input = document.getElementById('tableFilter');
  if (input) {
    var table = document.getElementById(input.getAttribute('data-table'));
    var select = document.getElementById('scopeFilter') || document.getElementById('verdictFilter');
    var attr = document.getElementById('scopeFilter') ? 'data-scope' : 'data-verdict';
    var rows = table.querySelectorAll('tbody tr');
    var count = document.querySelector('.rowcount[data-for="' + table.id + '"]');
    var apply = function () {
      var q = input.value.toLowerCase(), s = select ? select.value : '', shown = 0;
      for (var i = 0; i < rows.length; i++) {
        var r = rows[i];
        var ok = (!s || r.getAttribute(attr) === s) && (!q || r.textContent.toLowerCase().indexOf(q) !== -1);
        r.style.display = ok ? '' : 'none';
        if (ok) shown++;
      }
      if (count) count.textContent = shown + ' van ' + rows.length;
    };
    input.addEventListener('input', apply);
    if (select) select.addEventListener('change', apply);
    apply();
  }

  // Bevestiging bij verwijderen
  document.querySelectorAll('form[data-confirm]').forEach(function (f) {
    f.addEventListener('submit', function (e) {
      if (!window.confirm(f.getAttribute('data-confirm'))) e.preventDefault();
    });
  });

  // API-sleutel tonen en kopieren
  document.querySelectorAll('[data-toggle-secret]').forEach(function (b) {
    b.addEventListener('click', function () {
      var el = document.getElementById(b.getAttribute('data-toggle-secret'));
      el.type = el.type === 'password' ? 'text' : 'password';
      b.textContent = el.type === 'password' ? 'Toon' : 'Verberg';
    });
  });
  document.querySelectorAll('[data-copy]').forEach(function (b) {
    b.addEventListener('click', function () {
      var el = document.getElementById(b.getAttribute('data-copy'));
      navigator.clipboard.writeText(el.value).then(function () {
        b.textContent = 'Gekopieerd';
        setTimeout(function () { b.textContent = 'Kopieer'; }, 1500);
      });
    });
  });
})();
