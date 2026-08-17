import { useEffect, useState } from "react";
import { Copy, ExternalLink, X } from "lucide-react";
import { api } from "../api/client";
import StatusBadge from "./StatusBadge";
import { useToast } from "./useToast";

const APP_ID = import.meta.env.VITE_ALGORAND_APP_ID ?? "1010";

function formatDate(value) {
  if (!value) return "-";
  return new Date(value).toLocaleString("fr-FR", {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

function txUrl(txId) {
  return txId ? `https://lora.algokit.io/localnet/transaction/${encodeURIComponent(txId)}` : null;
}

function Field({ label, children, mono = false }) {
  return (
    <div>
      <dt className="text-[11px] font-medium uppercase tracking-wide text-ink/40">{label}</dt>
      <dd className={`mt-1 text-sm break-all ${mono ? "font-mono text-ink/70" : "text-ink"}`}>
        {children ?? "-"}
      </dd>
    </div>
  );
}

function CopyButton({ value, label }) {
  const showToast = useToast();

  async function copy() {
    if (!value) return;
    await navigator.clipboard.writeText(value);
    showToast(`${label} copié.`);
  }

  return (
    <button
      type="button"
      onClick={copy}
      title={`Copier ${label}`}
      className="rounded-md p-1.5 text-ink/35 hover:bg-ink/5 hover:text-ink"
    >
      <Copy size={14} />
    </button>
  );
}

export default function DeviceDetailPanel({ did, onClose }) {
  const [device, setDevice] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    api
      .getDeviceByDid(did)
      .then((data) => { if (!cancelled) setDevice(data); })
      .catch((e) => { if (!cancelled) setError(e.message); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [did]);

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div className="absolute inset-0 bg-ink/40" onClick={onClose} />
      <aside className="relative h-full w-full max-w-xl overflow-y-auto border-l border-ink/10 bg-white">
        <div className="sticky top-0 z-10 border-b border-ink/10 bg-white px-6 py-5">
          <div className="flex items-start justify-between gap-4">
            <div>
              <h2 className="font-display text-lg font-semibold">Identité du dispositif</h2>
              <p className="mt-1 text-xs text-ink/45">PostgreSQL, DID Algorand et cycle de vie local</p>
            </div>
            <button
              onClick={onClose}
              title="Fermer"
              className="rounded-md p-1.5 text-ink/40 hover:bg-ink/5 hover:text-ink"
            >
              <X size={18} />
            </button>
          </div>
        </div>

        <div className="p-6">
          {loading && <p className="text-sm text-ink/50">Chargement...</p>}
          {error && <p className="text-sm text-red-700">Erreur : {error}</p>}

          {device && (
            <div className="space-y-6">
              <section className="rounded-lg border border-ink/10 bg-paper/60 p-4">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="text-xs font-medium uppercase tracking-wide text-ink/40">Statut administratif</div>
                    <div className="mt-2"><StatusBadge status={device.status} /></div>
                  </div>
                  <div className="text-right">
                    <div className="text-xs font-medium uppercase tracking-wide text-ink/40">App Algorand</div>
                    <div className="mt-2 font-mono text-sm font-semibold">#{APP_ID}</div>
                  </div>
                </div>
              </section>

              <section>
                <h3 className="mb-3 font-display text-sm font-semibold">Identité locale</h3>
                <dl className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                  <Field label="Numéro de série">{device.serialNumber}</Field>
                  <Field label="Type">{device.deviceType}</Field>
                  <Field label="Emplacement">{device.location}</Field>
                  <Field label="Groupe logique">{device.logicalGroup}</Field>
                  <Field label="Responsable">{device.responsible}</Field>
                  <Field label="Adresse MAC">{device.macAddress}</Field>
                </dl>
              </section>

              <section>
                <h3 className="mb-3 font-display text-sm font-semibold">DID Algorand</h3>
                <dl className="space-y-4">
                  <div>
                    <dt className="text-[11px] font-medium uppercase tracking-wide text-ink/40">DID officiel</dt>
                    <dd className="mt-1 flex items-start gap-2">
                      <span className="break-all font-mono text-xs text-ink/70">{device.did || "-"}</span>
                      <CopyButton value={device.did} label="DID" />
                    </dd>
                  </div>
                  <div>
                    <dt className="text-[11px] font-medium uppercase tracking-wide text-ink/40">Clé publique Base32</dt>
                    <dd className="mt-1 flex items-start gap-2">
                      <span className="break-all font-mono text-xs text-ink/70">{device.publicKey || "-"}</span>
                      <CopyButton value={device.publicKey} label="clé publique" />
                    </dd>
                  </div>
                  <div>
                    <dt className="text-[11px] font-medium uppercase tracking-wide text-ink/40">Transaction d'enrôlement</dt>
                    <dd className="mt-1">
                      {device.algorandTxId ? (
                        <a
                          href={txUrl(device.algorandTxId)}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center gap-1 break-all font-mono text-xs text-seal hover:text-seal-dark"
                        >
                          {device.algorandTxId}
                          <ExternalLink size={13} />
                        </a>
                      ) : (
                        <span className="text-sm text-ink/40">-</span>
                      )}
                    </dd>
                  </div>
                </dl>
              </section>

              <section>
                <h3 className="mb-3 font-display text-sm font-semibold">Cycle de vie</h3>
                <dl className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                  <Field label="Créé le">{formatDate(device.createdAt)}</Field>
                  <Field label="Activé le">{formatDate(device.activatedAt)}</Field>
                  <Field label="Dernière activité">{formatDate(device.lastSeenAt)}</Field>
                  <Field label="Mis à jour le">{formatDate(device.updatedAt)}</Field>
                </dl>

                {device.status === "SUSPENDED" && (
                  <div className="mt-4 rounded-md border border-orange-200 bg-orange-50 p-3">
                    <Field label="Suspendu le">{formatDate(device.suspendedAt)}</Field>
                    <div className="mt-3">
                      <Field label="Motif de suspension">{device.suspensionReason}</Field>
                    </div>
                  </div>
                )}

                {device.status === "REVOKED" && (
                  <div className="mt-4 rounded-md border border-red-200 bg-red-50 p-3">
                    <Field label="Révoqué le">{formatDate(device.revokedAt)}</Field>
                    <div className="mt-3">
                      <Field label="Motif de révocation">{device.revocationReason}</Field>
                    </div>
                  </div>
                )}
              </section>
            </div>
          )}
        </div>
      </aside>
    </div>
  );
}
