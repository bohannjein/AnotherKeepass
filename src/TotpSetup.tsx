// TOTP setup inside the edit form: read a QR code image (pick, drop or paste) and
// preview the current code so the user sees the key works before saving.
import { useEffect, useRef, useState } from 'react';
import { normalizeTotp } from './model';
import { totp } from './totp';
import type { Strings } from './i18n';
import { Icon } from './Icon';

async function decodeQr(file: Blob): Promise<string | null> {
  const { default: jsQR } = await import('jsqr'); // only loaded when someone scans a QR code
  const bmp = await createImageBitmap(file);
  const canvas = new OffscreenCanvas(bmp.width, bmp.height);
  const ctx = canvas.getContext('2d')!;
  ctx.drawImage(bmp, 0, 0);
  const { data, width, height } = ctx.getImageData(0, 0, bmp.width, bmp.height);
  return jsQR(data, width, height)?.data ?? null;
}

const params = (uri: string) => {
  try { return new URL(uri).searchParams; } catch { return new URLSearchParams(); }
};

export function TotpSetup({ t, value, title, onChange, children }: {
  t: Strings; value: string; title: string; onChange: (v: string) => void; children: React.ReactNode;
}) {
  const [error, setError] = useState('');
  const [preview, setPreview] = useState<{ code: string; left: number } | null>(null);
  const [over, setOver] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  const readImage = async (file: Blob | null | undefined) => {
    if (!file || !file.type.startsWith('image/')) return;
    setError('');
    const text = await decodeQr(file).catch(() => null);
    // Google's export format (otpauth-migration://) carries several protobuf-encoded keys; not supported
    if (text?.toLowerCase().startsWith('otpauth://')) onChange(text);
    else setError(t.qrNotFound);
  };

  // live preview with the in-browser TOTP (same algorithm as the backend)
  useEffect(() => {
    const uri = normalizeTotp(value, title);
    if (!uri) { setPreview(null); return; }
    const p = params(uri);
    const period = Number(p.get('period')) || 30;
    const digits = Number(p.get('digits')) || 6;
    let live = true;
    const tick = () => {
      const now = Date.now();
      totp(uri, now, digits, period)
        .then(code => { if (live) { setPreview({ code, left: period - (Math.floor(now / 1000) % period) }); setError(e => e === t.invalidSecret ? '' : e); } })
        .catch(() => { if (live) { setPreview(null); setError(t.invalidSecret); } });
    };
    tick();
    const id = setInterval(tick, 1000);
    return () => { live = false; clearInterval(id); };
  }, [value, title, t.invalidSecret]);

  return (
    <div className={'totp-setup' + (over ? ' over' : '')}
      onDragOver={e => { if (e.dataTransfer.types.includes('Files')) { e.preventDefault(); setOver(true); } }}
      onDragLeave={() => setOver(false)}
      onDrop={e => { if (e.dataTransfer.files.length) { e.preventDefault(); setOver(false); readImage(e.dataTransfer.files[0]); } }}
      onPaste={e => {
        const img = [...e.clipboardData.items].find(i => i.type.startsWith('image/'));
        if (img) { e.preventDefault(); readImage(img.getAsFile()); }
      }}>
      {children}
      <div className="totp-tools">
      <button type="button" className="btn tonal" onClick={() => fileRef.current?.click()} title={t.qrHint}>
        <Icon n="qr_code_scanner" />{t.qrScan}
      </button>
      <input ref={fileRef} type="file" accept="image/*" hidden onChange={e => { readImage(e.target.files?.[0]); e.target.value = ''; }} />
      {preview && (
        <span className="totp-preview" title={t.totpPreview}>
          <Icon n="timer" />{preview.code.replace(/(\d{3})(?=\d)/g, '$1 ')}<small>{preview.left}s</small>
        </span>
      )}
      {error && <span className="form-error"><Icon n="error" />{error}</span>}
      {!preview && !error && <small className="totp-hint">{t.qrHint}</small>}
      </div>
    </div>
  );
}
