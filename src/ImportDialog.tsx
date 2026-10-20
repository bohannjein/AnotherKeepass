// Import dialog: pick an export file, preview what was found, choose the target vault.
// Loaded lazily (with its parsers) only when opened.
import { useRef, useState } from 'react';
import type { ImportInput } from './backend';
import type { Lang, Strings } from './i18n';
import { Icon } from './Icon';
import { parseImport, toImportInput, type ImportResult } from './importers';
import type { ItemType, VaultInfo } from './model';

const TEXT = {
  en: {
    title: 'Import', pick: 'Choose export file', formats: 'Bitwarden (.json, .csv), Proton Pass (.zip, .csv), 1Password (.1pux, .csv), KeePassXC, Chrome, Edge, Firefox, LastPass and other CSV files.',
    howTo: 'Export unencrypted from the other app, import here, then delete the export file.',
    found: 'entries found', skipped: 'skipped (trash/archive)', folders: 'folders', into: 'Into vault', newFolder: 'Put everything in a new folder',
    plain: 'The export file contains your passwords unencrypted. Delete it after the import.', go: 'Import', more: 'more',
    encrypted: 'This export is encrypted. Export again without a password (unencrypted JSON/CSV).', unknown: 'Unknown file format.', empty: 'No entries in this file.',
    done: 'entries imported',
  },
  de: {
    title: 'Importieren', pick: 'Exportdatei wählen', formats: 'Bitwarden (.json, .csv), Proton Pass (.zip, .csv), 1Password (.1pux, .csv), KeePassXC, Chrome, Edge, Firefox, LastPass und andere CSV-Dateien.',
    howTo: 'In der anderen App unverschlüsselt exportieren, hier importieren, danach die Exportdatei löschen.',
    found: 'Einträge gefunden', skipped: 'übersprungen (Papierkorb/Archiv)', folders: 'Ordner', into: 'In Tresor', newFolder: 'Alles in einen neuen Ordner legen',
    plain: 'Die Exportdatei enthält deine Passwörter unverschlüsselt. Lösche sie nach dem Import.', go: 'Importieren', more: 'weitere',
    encrypted: 'Dieser Export ist verschlüsselt. Bitte ohne Passwort exportieren (unverschlüsseltes JSON/CSV).', unknown: 'Unbekanntes Dateiformat.', empty: 'Keine Einträge in dieser Datei.',
    done: 'Einträge importiert',
  },
  fr: {
    title: 'Importer', pick: 'Choisir le fichier d’export', formats: 'Bitwarden (.json, .csv), Proton Pass (.zip, .csv), 1Password (.1pux, .csv), KeePassXC, Chrome, Edge, Firefox, LastPass et autres fichiers CSV.',
    howTo: 'Exportez sans chiffrement depuis l’autre application, importez ici, puis supprimez le fichier.',
    found: 'entrées trouvées', skipped: 'ignorées (corbeille/archive)', folders: 'dossiers', into: 'Dans le coffre', newFolder: 'Tout mettre dans un nouveau dossier',
    plain: 'Le fichier d’export contient vos mots de passe en clair. Supprimez-le après l’import.', go: 'Importer', more: 'de plus',
    encrypted: 'Cet export est chiffré. Exportez à nouveau sans mot de passe (JSON/CSV non chiffré).', unknown: 'Format de fichier inconnu.', empty: 'Aucune entrée dans ce fichier.',
    done: 'entrées importées',
  },
  es: {
    title: 'Importar', pick: 'Elegir archivo exportado', formats: 'Bitwarden (.json, .csv), Proton Pass (.zip, .csv), 1Password (.1pux, .csv), KeePassXC, Chrome, Edge, Firefox, LastPass y otros CSV.',
    howTo: 'Exporta sin cifrar desde la otra app, importa aquí y luego borra el archivo exportado.',
    found: 'entradas encontradas', skipped: 'omitidas (papelera/archivo)', folders: 'carpetas', into: 'En la bóveda', newFolder: 'Poner todo en una carpeta nueva',
    plain: 'El archivo exportado contiene tus contraseñas sin cifrar. Bórralo tras importar.', go: 'Importar', more: 'más',
    encrypted: 'Esta exportación está cifrada. Exporta de nuevo sin contraseña (JSON/CSV sin cifrar).', unknown: 'Formato de archivo desconocido.', empty: 'No hay entradas en este archivo.',
    done: 'entradas importadas',
  },
} satisfies Record<Lang, Record<string, string>>;

export default function ImportDialog({ t, lang, vaults, vault: initialVault, typeIcon, onClose, onImport }: {
  t: Strings; lang: Lang; vaults: VaultInfo[]; vault: string; typeIcon: Record<ItemType, string>;
  onClose: () => void; onImport: (vault: string, items: ImportInput[], doneText: string) => Promise<boolean>;
}) {
  const x = TEXT[lang];
  const file = useRef<HTMLInputElement>(null);
  const [result, setResult] = useState<ImportResult | null>(null);
  const [error, setError] = useState('');
  const [vault, setVault] = useState(vaults.some(v => v.id === initialVault) ? initialVault : vaults[0]?.id ?? '');
  const [ownFolder, setOwnFolder] = useState(true);
  const [busy, setBusy] = useState(false);

  const load = async (f: File) => {
    setError(''); setResult(null);
    try {
      const r = await parseImport(f.name, await f.arrayBuffer());
      if (!r.entries.length) throw new Error('empty');
      setResult(r);
    } catch (e) {
      const m = String(e instanceof Error ? e.message : e);
      setError(m === 'encrypted' ? x.encrypted : m === 'empty' ? x.empty : m === 'unknown_format' || e instanceof SyntaxError ? x.unknown : `${x.unknown} (${m})`);
    }
  };
  const go = async () => {
    if (!result) return;
    setBusy(true);
    const folder = `Import ${result.source.replace(/ \(CSV\)$/, '')} ${new Date().toISOString().slice(0, 10)}`;
    const items = result.entries.map(e => toImportInput(ownFolder ? { ...e, path: [folder, ...e.path] } : e));
    if (await onImport(vault, items, `${items.length} ${x.done}`)) onClose();
    setBusy(false);
  };
  const folderCount = result ? new Set(result.entries.map(e => e.path.join('/')).filter(Boolean)).size : 0;

  return (
    <div className="scrim" onClick={onClose}>
      <div className="dialog import-dialog" role="dialog" aria-label={x.title} onClick={e => e.stopPropagation()}
        onKeyDown={e => { if (e.key === 'Escape') onClose(); }}>
        <h3><Icon n="upload_file" />{x.title}</h3>
        <input ref={file} type="file" hidden accept=".csv,.json,.zip,.1pux,.txt"
          onChange={e => { const f = e.target.files?.[0]; if (f) load(f); e.target.value = ''; }} />
        {!result && (
          <>
            <p className="dialog-body">{x.formats}</p>
            <p className="dialog-body">{x.howTo}</p>
            <button className="btn tonal" autoFocus onClick={() => file.current?.click()}><Icon n="folder_open" />{x.pick}</button>
          </>
        )}
        {error && <p className="form-error" role="alert"><Icon n="error" />{error}</p>}
        {result && (
          <>
            <p className="dialog-body">
              <b>{result.source}</b>: {result.entries.length} {x.found}
              {folderCount > 0 && <> · {folderCount} {x.folders}</>}
              {result.skipped > 0 && <> · {result.skipped} {x.skipped}</>}
            </p>
            <ul className="import-preview">
              {result.entries.slice(0, 6).map((e, i) => (
                <li key={i}><Icon n={typeIcon[e.type]} /><span>{e.title || t.untitled}</span>{e.path.length > 0 && <small>{e.path.join(' / ')}</small>}</li>
              ))}
              {result.entries.length > 6 && <li className="more">+ {result.entries.length - 6} {x.more}</li>}
            </ul>
            {vaults.length > 1 && (
              <label className="opt">{x.into}
                <select className="set-select" value={vault} onChange={e => setVault(e.target.value)}>
                  {vaults.map(v => <option key={v.id} value={v.id}>{v.name}</option>)}
                </select>
              </label>
            )}
            <label className="opt">{x.newFolder}<input className="switch" type="checkbox" checked={ownFolder} onChange={e => setOwnFolder(e.target.checked)} /></label>
            <p className="form-note"><Icon n="warning" />{x.plain}</p>
          </>
        )}
        <div className="row">
          <button className="btn text" onClick={onClose}>{t.cancel}</button>
          {result && <button className="btn filled" disabled={busy || !vault} onClick={go}><Icon n="download" />{x.go}</button>}
        </div>
      </div>
    </div>
  );
}
