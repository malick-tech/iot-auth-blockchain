import { useState } from "react";
import { AlertTriangle } from "lucide-react";

const ACTION_CONFIG = {
  suspend: {
    title: "Suspendre le dispositif",
    description: "Le dispositif ne pourra plus s'authentifier tant qu'il n'est pas réactivé. Cette action est réversible.",
    confirmLabel: "Suspendre",
    confirmClass: "bg-orange-600 hover:bg-orange-700",
    requireReason: true,
    defaultReason: "Suspension manuelle (dashboard)",
  },
  revoke: {
    title: "Révoquer le dispositif",
    description: "Cette action est IRRÉVERSIBLE et publie une transaction sur la blockchain Algorand. Le dispositif perdra définitivement son identité.",
    confirmLabel: "Révoquer définitivement",
    confirmClass: "bg-red-600 hover:bg-red-700",
    requireReason: true,
    defaultReason: "",
  },
};

export default function ConfirmActionModal({ action, onConfirm, onCancel }) {
  const config = ACTION_CONFIG[action];
  const [reason, setReason] = useState(config.defaultReason);

  const canConfirm = !config.requireReason || reason.trim().length > 0;

  return (
    <div className="fixed inset-0 bg-ink/40 flex items-center justify-center px-4 z-50">
      <div className="bg-white rounded-lg border border-ink/10 shadow-xl w-full max-w-sm p-6">
        <div className="flex items-start gap-3 mb-4">
          <div className={`p-2 rounded-full ${action === "revoke" ? "bg-red-50 text-red-600" : "bg-orange-50 text-orange-600"}`}>
            <AlertTriangle size={18} />
          </div>
          <div>
            <h2 className="font-display text-base font-semibold">{config.title}</h2>
            <p className="text-sm text-ink/50 mt-1">{config.description}</p>
          </div>
        </div>

        <div className="mb-5">
          <label className="block text-xs font-medium text-ink/60 mb-1">Motif</label>
          <textarea
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            rows={2}
            className="w-full px-3 py-2 border border-ink/15 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-seal/40"
            placeholder="Décris la raison de cette action..."
          />
        </div>

        <div className="flex justify-end gap-2">
          <button
            onClick={onCancel}
            className="px-4 py-2 text-sm rounded-md border border-ink/15 hover:bg-ink/5"
          >
            Annuler
          </button>
          <button
            onClick={() => onConfirm(reason)}
            disabled={!canConfirm}
            className={`px-4 py-2 text-sm rounded-md text-white disabled:opacity-40 ${config.confirmClass}`}
          >
            {config.confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
