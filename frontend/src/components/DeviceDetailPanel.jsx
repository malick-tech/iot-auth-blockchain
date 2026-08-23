import { useEffect, useRef, useState } from "react";
import { Ban, Copy, ExternalLink, Loader2, Pause, Play, X } from "lucide-react";
import { api } from "../api/client";
import StatusBadge from "./StatusBadge";
import { useToast } from "./useToast";
import { useFocusTrap } from "../hooks/useFocusTrap";
import { formatDate, txUrl } from "../utils/format";

const APP_ID = import.meta.env.VITE_ALGORAND_APP_ID ?? "1010";

function Field({ label, children, mono = false }) {
  return (
    <div>
      <dt className="text-[11px] font-medium uppercase tracking-wide text-ink/40">{label}</dt>
      <dd className={`mt-1 break-all text-sm ${mono ? "font-mono text-ink/70" : "text-ink"}`}>
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
      aria-label={`Copier ${label}`}
      className="rounded-md p-1.5 text-ink/35 hover:bg-ink/5 hover:text-ink"
    >
      <Copy size={14} aria-hidden="true" />
    </button>
  );
}

/**
 * Panneau de détail d'un dispositif (slide-over latéral).
 * Inclut les boutons d'action Suspendre / Réactiver / Révoquer.
 *
 * Props :
 *   did          – DID du dispositif à afficher
 *   onClose      – fermeture du panneau
 *   onActionDone – callback appelé après une action réussie pour rafraîchir la liste parente
 *   onRevoke     – ouvre la modale de confirmation révocation (nécessite motif)
 *   onSuspend    – ouvre la modale de confirmation suspension (nécessite motif)
 */
export default function DeviceDetailPanel({ did, onClose, onActionDone, onRevoke, onSuspend }) {
  const [device, setDevice]   = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);
  const [busy, setBusy]       = useState(false);
  const panelRef              = useRef(null);
  const showToast             = useToast();

  // Tâche 8 : focus trap + Escape
  useFocusTrap(panelRef, true, onClose);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    api
      .getDeviceByDid(did)
      .then((data)  => { if (!cancelled) setDevice(data); })
      .catch((e)    => { if (!cancelled) setError(e.message); })
      .finally(()   => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [did]);

  async function handleReactivate() {
    setBusy(true);
    try {
      await api.reactivateDevice(did);
      showToast("Dispositif réactivé.");
      onActionDone?.();
      onClose();
    } catch (e) {
      showToast(e.message, "error");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-ink/40"
        aria-hidden="true"
        onClick={onClose}
      />

      {/* Panel */}
      <aside
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="device-panel-title"
        className="relative flex h-full w-full max-w-xl flex-col overflow-hidden border-l border-ink/10 bg-white"
      >
        {/* En-tête sticky */}
        <div className="sticky top-0 z-10 border-b border-ink/10 bg-white px-6 py-5">
          <div className="flex items-start justify-between gap-4">
            <div>
              <h2 id="device-panel-title" className="font-display text-lg font-semibold">
                Identité du dispositif
              </h2>
              <p className="mt-1 text-xs text-ink/45">PostgreSQL, DID Algorand et cycle de vie local</p>
            </div>
            <button
              onClick={onClose}
              aria-label="Fermer le panneau"
              className="rounded-md p-1.5 text-ink/40 hover:bg-ink/5 hover:text-ink"
            >
              <X size={18} aria-hidden="true" />
            </button>
          </div>
        </div>

        {/* Corps scrollable */}
        <div className="flex-1 overflow-y-auto p-6">
          {loading && (
            <div role="status" aria-label="Chargement…" className="space-y-3">
              {Array.from({ length: 6 }).map((_, i) => (
                <div key={i} className="h-4 animate-pulse rounded bg-ink/[0.06]" style={{ width: `${50 + i * 8}%` }} />
              ))}
            </div>
          )}
          {error && (
            <p role="alert" className="text-sm text-red-700">Erreur : {error}</p>
          )}

          {device && (
            <div className="space-y-6">
              {/* Statut + App ID */}
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

              {/* Identité locale */}
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

              {/* DID Algorand */}
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
                          aria-label={`Voir la transaction ${device.algorandTxId} sur Lora`}
                          className="inline-flex items-center gap-1 break-all font-mono text-xs text-seal hover:text-seal-dark"
                        >
                          {device.algorandTxId}
                          <ExternalLink size={13} aria-hidden="true" />
                        </a>
                      ) : (
                        <span className="text-sm text-ink/40">-</span>
                      )}
                    </dd>
                  </div>
                </dl>
              </section>

              {/* Cycle de vie */}
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

              {/* Tâche 9 : Actions depuis le panneau de détail */}
              {(device.status === "ACTIVE" || device.status === "SUSPENDED") && (
                <section>
                  <h3 className="mb-3 font-display text-sm font-semibold">Actions</h3>
                  <div className="flex flex-wrap gap-2">
                    {device.status === "ACTIVE" && (
                      <button
                        disabled={busy}
                        onClick={() => { onClose(); onSuspend?.(device.did); }}
                        aria-label="Suspendre ce dispositif"
                        className="inline-flex items-center gap-2 rounded-md border border-orange-200 bg-orange-50 px-3 py-2 text-sm text-orange-700 hover:bg-orange-100 disabled:opacity-40"
                      >
                        <Pause size={14} aria-hidden="true" />
                        Suspendre
                      </button>
                    )}
                    {device.status === "SUSPENDED" && (
                      <button
                        disabled={busy}
                        onClick={handleReactivate}
                        aria-label="Réactiver ce dispositif"
                        className="inline-flex items-center gap-2 rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm text-emerald-700 hover:bg-emerald-100 disabled:opacity-40"
                      >
                        {busy
                          ? <Loader2 size={14} className="animate-spin" aria-hidden="true" />
                          : <Play    size={14} aria-hidden="true" />}
                        Réactiver
                      </button>
                    )}
                    <button
                      disabled={busy}
                      onClick={() => { onClose(); onRevoke?.(device.did); }}
                      aria-label="Révoquer définitivement ce dispositif"
                      className="inline-flex items-center gap-2 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700 hover:bg-red-100 disabled:opacity-40"
                    >
                      <Ban size={14} aria-hidden="true" />
                      Révoquer
                    </button>
                  </div>
                </section>
              )}
            </div>
          )}
        </div>
      </aside>
    </div>
  );
}
