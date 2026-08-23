import { useRef, useState } from "react";
import { ArrowRight, Database, Fingerprint, ShieldCheck, X } from "lucide-react";
import { api } from "../api/client";
import { useFocusTrap } from "../hooks/useFocusTrap";

const DEVICE_TYPES = ["capteur-temperature", "capteur-humidite", "actionneur", "passerelle"];

export default function EnrollDeviceForm({ responsible, onEnrolled, onClose }) {
  const [form, setForm] = useState({
    serialNumber: "",
    deviceType:   DEVICE_TYPES[0],
    location:     "",
    logicalGroup: "",
    responsible:  responsible || "",
  });
  const [submitting, setSubmitting] = useState(false);
  const [error, setError]           = useState(null);
  const dialogRef                   = useRef(null);

  // Tâche 8 : focus trap + Escape
  useFocusTrap(dialogRef, true, onClose);

  function update(field, value) {
    setForm((prev) => ({ ...prev, [field]: value }));
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      await api.registerDevice(form);
      onEnrolled();
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    /* Backdrop */
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-ink/40 px-4"
      aria-hidden="true"
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      {/* Dialog */}
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="enroll-modal-title"
        className="w-full max-w-2xl rounded-lg border border-ink/10 bg-white p-6 shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-4 flex items-start justify-between gap-4">
          <div>
            <h2 id="enroll-modal-title" className="font-display text-lg font-semibold">
              Pré-enregistrer un dispositif
            </h2>
            <p className="mt-0.5 text-sm text-ink/50">
              Crée l'identité locale avant le premier contact sécurisé.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Fermer la fenêtre"
            className="rounded-md p-1.5 text-ink/40 hover:bg-ink/5 hover:text-ink"
          >
            <X size={18} aria-hidden="true" />
          </button>
        </div>

        {/* Étapes visuelles */}
        <div className="mb-5 grid gap-2 rounded-lg border border-ink/10 bg-paper/60 p-3 text-xs text-ink/55 sm:grid-cols-[1fr_auto_1fr_auto_1fr] sm:items-center">
          <div className="flex items-center gap-2">
            <Database size={15} className="text-sky-600" aria-hidden="true" />
            <span>Pré-enregistré</span>
          </div>
          <ArrowRight size={14} className="hidden text-ink/30 sm:block" aria-hidden="true" />
          <div className="flex items-center gap-2">
            <Fingerprint size={15} className="text-amber-600" aria-hidden="true" />
            <span>Challenge PoP</span>
          </div>
          <ArrowRight size={14} className="hidden text-ink/30 sm:block" aria-hidden="true" />
          <div className="flex items-center gap-2">
            <ShieldCheck size={15} className="text-emerald-600" aria-hidden="true" />
            <span>DID actif</span>
          </div>
        </div>

        {error && (
          <div role="alert" className="mb-4 rounded-md bg-red-50 px-3 py-2 text-sm text-red-800">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4" noValidate>
          <div className="grid gap-3 sm:grid-cols-2">
            <div>
              <label htmlFor="serial-number" className="mb-1 block text-xs font-medium text-ink/60">
                Numéro de série <span className="text-red-500" aria-label="obligatoire">*</span>
              </label>
              <input
                id="serial-number"
                required
                value={form.serialNumber}
                onChange={(e) => update("serialNumber", e.target.value)}
                className="w-full rounded-md border border-ink/15 px-3 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-seal/40"
                placeholder="IOT-2026-001"
              />
            </div>

            <div>
              <label htmlFor="device-type" className="mb-1 block text-xs font-medium text-ink/60">
                Type de dispositif
              </label>
              <select
                id="device-type"
                value={form.deviceType}
                onChange={(e) => update("deviceType", e.target.value)}
                className="w-full rounded-md border border-ink/15 bg-white px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-seal/40"
              >
                {DEVICE_TYPES.map((t) => (
                  <option key={t} value={t}>{t}</option>
                ))}
              </select>
            </div>
          </div>

          <div>
            <label htmlFor="location" className="mb-1 block text-xs font-medium text-ink/60">
              Emplacement <span className="text-red-500" aria-label="obligatoire">*</span>
            </label>
            <input
              id="location"
              required
              value={form.location}
              onChange={(e) => update("location", e.target.value)}
              className="w-full rounded-md border border-ink/15 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-seal/40"
              placeholder="Ziguinchor-Lab"
            />
          </div>

          <div className="grid gap-3 sm:grid-cols-2">
            <div>
              <label htmlFor="logical-group" className="mb-1 block text-xs font-medium text-ink/60">
                Groupe logique
              </label>
              <input
                id="logical-group"
                value={form.logicalGroup}
                onChange={(e) => update("logicalGroup", e.target.value)}
                className="w-full rounded-md border border-ink/15 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-seal/40"
                placeholder="zone-a"
              />
            </div>
            <div>
              <label htmlFor="responsible" className="mb-1 block text-xs font-medium text-ink/60">
                Responsable
              </label>
              <input
                id="responsible"
                value={form.responsible}
                readOnly
                aria-readonly="true"
                className="w-full cursor-not-allowed rounded-md border border-ink/10 bg-ink/[0.03] px-3 py-2 text-sm text-ink/65 focus:outline-none"
              />
            </div>
          </div>

          <div className="flex flex-col gap-3 pt-2 sm:flex-row sm:items-center sm:justify-between">
            <p className="text-xs text-ink/40">Statut initial : PENDING</p>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={onClose}
                className="rounded-md border border-ink/15 px-4 py-2 text-sm hover:bg-ink/5"
              >
                Annuler
              </button>
              <button
                type="submit"
                disabled={submitting}
                className="rounded-md bg-seal px-4 py-2 text-sm text-white hover:bg-seal-dark disabled:opacity-50"
              >
                {submitting ? "Enregistrement…" : "Pré-enregistrer"}
              </button>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
}
