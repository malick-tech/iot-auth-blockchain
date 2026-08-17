import { useState } from "react";
import { ArrowRight, Database, Fingerprint, ShieldCheck, X } from "lucide-react";
import { api } from "../api/client";

const DEVICE_TYPES = ["capteur-temperature", "capteur-humidite", "actionneur", "passerelle"];

export default function EnrollDeviceForm({ onEnrolled, onClose }) {
  const [form, setForm] = useState({
    serialNumber: "",
    deviceType: DEVICE_TYPES[0],
    location: "",
    logicalGroup: "",
    responsible: "",
  });
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);

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
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-ink/40 px-4">
      <div className="w-full max-w-2xl rounded-lg border border-ink/10 bg-white p-6 shadow-xl">
        <div className="mb-4 flex items-start justify-between gap-4">
          <div>
            <h2 className="font-display text-lg font-semibold">Pré-enregistrer un dispositif</h2>
            <p className="mt-0.5 text-sm text-ink/50">Crée l'identité locale avant le premier contact sécurisé.</p>
          </div>
          <button
            onClick={onClose}
            title="Fermer"
            className="rounded-md p-1.5 text-ink/40 hover:bg-ink/5 hover:text-ink"
          >
            <X size={18} />
          </button>
        </div>

        <div className="mb-5 grid gap-2 rounded-lg border border-ink/10 bg-paper/60 p-3 text-xs text-ink/55 sm:grid-cols-[1fr_auto_1fr_auto_1fr] sm:items-center">
          <div className="flex items-center gap-2">
            <Database size={15} className="text-sky-600" />
            <span>Pré-enregistré</span>
          </div>
          <ArrowRight size={14} className="hidden text-ink/30 sm:block" />
          <div className="flex items-center gap-2">
            <Fingerprint size={15} className="text-amber-600" />
            <span>Challenge PoP</span>
          </div>
          <ArrowRight size={14} className="hidden text-ink/30 sm:block" />
          <div className="flex items-center gap-2">
            <ShieldCheck size={15} className="text-emerald-600" />
            <span>DID actif</span>
          </div>
        </div>

        {error && (
          <div className="mb-4 rounded-md bg-red-50 px-3 py-2 text-sm text-red-800">{error}</div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-2">
            <div>
              <label className="mb-1 block text-xs font-medium text-ink/60">Numéro de série</label>
              <input
                required
                value={form.serialNumber}
                onChange={(e) => update("serialNumber", e.target.value)}
                className="w-full rounded-md border border-ink/15 px-3 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-seal/40"
                placeholder="IOT-2026-001"
              />
            </div>

            <div>
              <label className="mb-1 block text-xs font-medium text-ink/60">Type de dispositif</label>
              <select
                value={form.deviceType}
                onChange={(e) => update("deviceType", e.target.value)}
                className="w-full rounded-md border border-ink/15 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-seal/40"
              >
                {DEVICE_TYPES.map((t) => (
                  <option key={t} value={t}>{t}</option>
                ))}
              </select>
            </div>
          </div>

          <div>
            <label className="mb-1 block text-xs font-medium text-ink/60">Emplacement</label>
            <input
              required
              value={form.location}
              onChange={(e) => update("location", e.target.value)}
              className="w-full rounded-md border border-ink/15 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-seal/40"
              placeholder="Ziguinchor-Lab"
            />
          </div>

          <div className="grid gap-3 sm:grid-cols-2">
            <div>
              <label className="mb-1 block text-xs font-medium text-ink/60">Groupe logique</label>
              <input
                value={form.logicalGroup}
                onChange={(e) => update("logicalGroup", e.target.value)}
                className="w-full rounded-md border border-ink/15 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-seal/40"
                placeholder="zone-a"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-ink/60">Responsable</label>
              <input
                value={form.responsible}
                onChange={(e) => update("responsible", e.target.value)}
                className="w-full rounded-md border border-ink/15 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-seal/40"
                placeholder="Equipe sécurité"
              />
            </div>
          </div>

          <div className="flex flex-col gap-3 pt-2 sm:flex-row sm:items-center sm:justify-between">
            <p className="text-xs text-ink/40">Statut initial: PRE_REGISTERED</p>
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
                {submitting ? "Enregistrement..." : "Pré-enregistrer"}
              </button>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
}
