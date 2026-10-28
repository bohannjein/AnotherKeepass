// Fills in the latest release (version, date, direct asset links) and picks the download for the
// visitor's OS. Without JS or without the GitHub API, every link still points to releases/latest.
(() => {
  const ua = navigator.userAgent;
  const mobile = /Android|iPhone|iPad|iPod/.test(ua);
  const linux = !mobile && /Linux|X11/.test(ua);
  if (mobile) document.documentElement.classList.add('is-mobile');

  const primary = document.querySelector('[data-dl="primary"]');
  if (linux && primary) {
    primary.querySelector('[data-dl-label]').textContent = 'Für Linux herunterladen';
    primary.querySelector('[data-dl-sub]').textContent = 'AppImage, Vorschau';
    document.querySelector('[data-dl-other]').textContent = 'Windows und weitere Optionen';
  }

  const mb = n => (n / 1048576).toFixed(1).replace('.', ',') + ' MB';
  fetch('https://api.github.com/repos/bohannjein/AnotherKeepass/releases/latest')
    .then(r => r.ok ? r.json() : Promise.reject(r.status))
    .then(rel => {
      const v = rel.tag_name.replace(/^v/, '');
      const date = new Date(rel.published_at).toLocaleDateString('de-DE', { day: 'numeric', month: 'long', year: 'numeric' });
      const assets = {
        win: rel.assets.find(a => /-setup\.exe$/i.test(a.name)),
        linux: rel.assets.find(a => /\.AppImage$/i.test(a.name)),
      };
      for (const [os, a] of Object.entries(assets)) {
        if (!a) continue;
        document.querySelectorAll(`[data-asset="${os}"]`).forEach(el => { el.href = a.browser_download_url; });
        document.querySelectorAll(`[data-size="${os}"]`).forEach(el => { el.textContent = mb(a.size); });
      }
      const mine = assets[linux ? 'linux' : 'win'];
      if (primary && mine) primary.href = mine.browser_download_url;
      document.querySelectorAll('[data-version-line]').forEach(el => { el.textContent = `Version ${v} · kostenlos, GPL-3.0`; });
      document.querySelectorAll('[data-version-big]').forEach(el => { el.textContent = `Version ${v} vom ${date}`; });
    })
    .catch(() => {});
})();
