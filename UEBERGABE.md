# Übergabe: AnotherKeepass weiterentwickeln

Stand: 25.10.2026 · Version **0.2.0** · Branch `main` · Repo: https://github.com/bohannjein/AnotherKeepass

Zuerst lesen: [README.md](README.md) (Bauen, Tests), [ARCHITECTURE.md](ARCHITECTURE.md) (wo was liegt),
[CONTRIBUTING.md](CONTRIBUTING.md) (Regeln), [CHANGELOG.md](CHANGELOG.md) (was drin ist).

---

## 1. Neuen Rechner einrichten

**Benötigt (Windows):**
- Git und **Node.js 24** (`node --version`)
- **Rust stable** über https://rustup.rs (`rustc --version`, gebaut mit 1.90)
- **Visual Studio Build Tools**, Workload „Desktopentwicklung mit C++“ (für Rust und Tauri)
- **WebView2-Runtime**: ist in Windows 11 schon dabei
- Optional für die Prüfungen: `cargo install cargo-audit`

```bash
git clone https://github.com/bohannjein/AnotherKeepass.git
```
```bash
cd AnotherKeepass && npm ci
```

**Git-Identität für dieses Repo:**

```bash
git config user.name "Johann"
```
```bash
git config user.email "jofecrow@tuta.com"
```

Wichtig, weil das Repo öffentlich ist: keine Firmen-Mail als Autor verwenden.

**Update-Signaturschlüssel:** Nur nötig, wenn du lokal ein Release mit Update-Paketen bauen willst. Für normales Entwickeln braucht es ihn nicht, GitHub hat ihn als Secret.
- Datei: `%USERPROFILE%\.tauri\anotherkeepass.key`, dazu `anotherkeepass.key.pub`.
- **Nie committen und nie in Chats kopieren.** Sicher übertragen, z. B. als Anhang eines Eintrags in deinem Tresor.
- Geht der Schlüssel verloren, kann keine installierte Version mehr Updates annehmen.

---

## 2. Täglich arbeiten

```bash
npm run dev
```
Startet eine Vorschau im Browser mit Demo-Tresoren. Jedes Passwort funktioniert.

```bash
npx tauri dev
```
Startet die echte Desktop-App mit echten `.kdbx`-Dateien.

**Prüfungen vor jedem Push.** Die CI führt genau diese Befehle aus; ist eine rot, wird nicht gemergt.

```bash
npm run check
```
```bash
cd src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test --lib && cargo audit
```
```bash
cd src-tauri && cargo test --lib browser_pipe_e2e -- --ignored
```

**Lokal den Installer bauen.** Das Ergebnis liegt in `src-tauri/target/release/bundle/nsis/`.

```bash
npx tauri build --bundles nsis
```

Läuft die App noch, ist `anotherkeepass.exe` gesperrt. Dann vorher umbenennen:

```bash
mv -f src-tauri/target/release/anotherkeepass.exe src-tauri/target/release/anotherkeepass.old.exe
```

---

## 3. Ein Release machen

1. Die Versionsnummer an drei Stellen erhöhen:
   - `package.json`
   - `src-tauri/Cargo.toml`
   - `src-tauri/tauri.conf.json`
2. Einen Abschnitt in `CHANGELOG.md` schreiben, committen und pushen.
3. Das Tag setzen und pushen:
   ```bash
   git tag -a v0.3.0 -m "AnotherKeepass 0.3.0"
   ```
   ```bash
   git push origin v0.3.0
   ```
   Ein Tag mit Bindestrich, z. B. `v0.3.0-beta.1`, wird als Vorabversion veröffentlicht.
4. Der Workflow `.github/workflows/build.yml` baut Windows (NSIS) und Linux (AppImage), signiert die Update-Pakete und legt einen **Entwurf** an. Er braucht etwa 8 Minuten.
5. Unter https://github.com/bohannjein/AnotherKeepass/releases den Entwurf prüfen. Erwartete Dateien:
   - `.exe` mit `.sig`
   - `.AppImage` mit `.sig`
   - `latest.json`

   Dann **Publish**. Erst danach sehen installierte Apps das Update.

**Secrets auf GitHub:** Settings → Secrets and variables → Actions → Repository secrets.
- `TAURI_SIGNING_PRIVATE_KEY` = kompletter Inhalt der `.key`-Datei: 348 Zeichen, endet auf `==`.
- Ein Passwort-Secret gibt es nicht, der Schlüssel hat keins.
- Der Workflow prüft den Schlüssel vor dem Bauen und meldet einen fehlenden oder abgeschnittenen Schlüssel sofort.

**Logs der GitHub Actions** sieht man nur eingeloggt. Fehlermeldungen erscheinen aber auch als Annotation auf der Seite des Laufs.

---

## 4. Offene Punkte

| Thema | Stand | Nächster Schritt |
|---|---|---|
| **Code-Signatur Windows** (gegen Defender/SmartScreen) | SignPath Foundation (kostenlos für Open Source) beantragt bzw. zu beantragen | Nach der Zusage den SignPath-Schritt in `build.yml` einbauen; Projekt-Slug und Token kommen als Secrets dazu |
| **Defender-Fehlalarm** `Trojan:Win32/Bearfoos.B!ml` | Meldung an Microsoft (wdsi/filesubmission) ist geplant oder läuft | Jede neue Version wieder einreichen, bis signiert wird |
| **GitHub-Cache alter Commits** (alte Autor-Mail) | Support-Ticket gestellt | Abwarten |
| **Linux: Entsperren ohne Windows Hello** | Hello und andere reine Windows-Optionen sind unter Linux ausgeblendet | Polkit-Entsperren (Fingerabdruck/Systempasswort) wie bei KeePassXC; braucht eine Policy-Datei, also ein `.deb`/`.rpm`-Paket oder einen manuellen Installationsschritt |
| **Linux allgemein** | AppImage baut, ist aber auf Linux ungetestet | Auto-Type-Fenstererkennung, Browser-Manifeste und Sperren bei Bildschirmsperre fehlen noch (im Code als `ponytail:` markiert) |
| **App.tsx** | rund 820 Zeilen; die Komponente `Vaults` ist noch groß | In weitere Hooks bzw. Komponenten zerlegen, z. B. die Seitenleiste |
| **Organisationen in Vaultwarden** | schreibbar, aber nur gegen einen Test-Server geprüft | Mit dem echten Vaultwarden testen; Verschieben zwischen Sammlungen wird nicht unterstützt |
| **M9: eigene Browser-Erweiterung** | nur geplant | Siehe Plan: Manifest V3, eigene Kopplung, Passkeys direkt in der Erweiterung |
| **Impeccable-Skill** | v4.7.0 verfügbar | `npx impeccable update` bei Bedarf |

---

## 5. Stolpersteine

- **Defender meldet frische Builds als Trojaner:** Das ist ein KI-Fehlalarm bei unsignierten Programmen. Keine Ausnahme im Defender eintragen, sondern melden bzw. signieren lassen.
- **Upgrade von 0.1.0:** Mit 0.2.0 hat sich der Herausgeber geändert (`bohannjein`). Eine Installation von 0.1.0 muss daher einmal von Hand deinstalliert werden. Dabei **App-Daten nicht löschen**.
- **TeamViewer:** Ist der Bildschirmschutz aus, malt TeamViewer versteckte Fenster mit. Deshalb wird das Schnellzugriff-Fenster nur erzeugt, wenn es gebraucht wird.
- **Prozess-Härtung** (`src-tauri/src/hardening.rs`): Zum Eingrenzen von Fehlern die App mit `AKP_NO_HARDENING=1` starten, dann ist die Härtung aus.
- **Die gemerkte Tresor-Liste** liegt im WebView-Speicher (localStorage), nicht in den `.kdbx`-Dateien. Ist sie leer, die Tresore einmal über „Datei wählen“ öffnen.
- **Beim Pushen** werden Tags und Commits nie mit force überschrieben, außer bei einem Release-Tag, das noch nie veröffentlicht wurde.
