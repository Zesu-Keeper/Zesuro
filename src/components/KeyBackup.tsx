"use client";

import { useEffect, useState } from "react";
import QRCode from "qrcode";
import { exportKeyString, type StoredKey } from "@/lib/client-crypto";

/**
 * Shows the device key as a QR code. The user must save it (download or copy) and tick the
 * box before continuing. Anyone holding this code can reveal the author of entries, so it
 * is treated like a password.
 */
export default function KeyBackup({
  k,
  onConfirmed,
  onCancel,
  onSkip,
  confirmLabel = "Continue",
}: {
  k: StoredKey;
  onConfirmed: () => void;
  onCancel?: () => void;
  /** Offered for dated entries: they reveal on their date without the key. */
  onSkip?: () => void;
  confirmLabel?: string;
}) {
  const text = exportKeyString(k);
  const [png, setPng] = useState<string | null>(null);
  const [touched, setTouched] = useState(false);
  const [checked, setChecked] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let live = true;
    QRCode.toDataURL(text, { errorCorrectionLevel: "M", margin: 2, width: 640 }).then((u) => {
      if (live) setPng(u);
    });
    return () => {
      live = false;
    };
  }, [text]);

  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTouched(true);
    } catch {
      /* clipboard blocked: user can still download */
    }
  }

  return (
    <div>
      <h2>Save your key</h2>
      <p className="lede">
        Your key is the only thing that proves your posts are yours. Save it somewhere safe, like
        your photos, a password manager, or a printout.{" "}
        <a href="/help#your-key" target="_blank" rel="noopener noreferrer">Why?</a>
      </p>
      {png ? (
        // eslint-disable-next-line @next/next/no-img-element
        <img className="qr" src={png} alt="QR code containing your Zesuro key" />
      ) : (
        <p className="empty">Making your code…</p>
      )}
      <div className="row" style={{ justifyContent: "center" }}>
        {png ? (
          <a
            className="btn"
            href={png}
            download="zesuro-key.png"
            onClick={() => setTouched(true)}
          >
            Download QR
          </a>
        ) : null}
        <button type="button" onClick={copy}>
          {copied ? "Copied" : "Copy as text"}
        </button>
      </div>
      <div className="warnbox">
        Treat this like a password. Anyone who has it can reveal your posts. If you lose it and
        this device is wiped, you will never be able to reveal them.
      </div>
      <label className="opt" style={{ cursor: touched ? "pointer" : "not-allowed" }}>
        <input
          type="checkbox"
          checked={checked}
          disabled={!touched}
          onChange={(e) => setChecked(e.target.checked)}
        />
        I have saved my key somewhere safe
      </label>
      <div className="row">
        {onCancel ? (
          <button type="button" className="link" onClick={onCancel}>
            Cancel
          </button>
        ) : (
          <span />
        )}
        <button type="button" className="primary" disabled={!(touched && checked)} onClick={onConfirmed}>
          {confirmLabel}
        </button>
      </div>
      {onSkip ? (
        <p className="count" style={{ textAlign: "center" }}>
          This post will still reveal itself on its date without the key. You only need the key if
          you want to reveal it sooner, or use another device.{" "}
          <button type="button" className="link" onClick={onSkip}>
            Skip and seal
          </button>
        </p>
      ) : null}
    </div>
  );
}
