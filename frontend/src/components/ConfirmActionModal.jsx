import { useRef, useState } from "react";
import { AlertTriangle } from "lucide-react";
import { useFocusTrap } from "../hooks/useFocusTrap";

const ACTION_CONFIG = {
  suspend: {
    title:         "Suspendre le dispositif",
    description:   "Le dispositif ne pourra plus s'authentifier tant qu'il n'est pas réactivé. Cette action est réversible.",
    confirmLabel:  "Suspendre",
    confirmClass:  "bg-orange-600 hover:bg-orange-700",
    requireReason: true,
    defaultReason: "Suspension manuelle (dashboard)",
  },
  revoke: {
    title:         "Révoquer le dispositif",
    description:   "Cette action est IRRÉVERSIBLE et publie une transaction sur la blockchain Algorand. Le dispositif perdra définitivement son identité.",
    confirmLabel:  "Révoquer définitivement",
    confirmClass:  "bg-red-600 hover:bg-red-700",
    requireReason: true,
    defaultReason: "",
  },
};

export default function ConfirmActionModal({ action, onConfirm, onCancel }) {
  const config     = ACTION_CONFIG[action];
  const [reason, setReason] = useState(config.defaultReason);
  const dialogRef  = useRef(null);

  // Tâche 8 : focus trap + fermeture Escape
  useFocusTrap(dialogRef, true, onCancel);

  const canConfirm = !config.requireReason || reason.trim().length > 0;
  const titleId    = `confirm-modal-title-${action}`;
  const descId     = `confirm-modal-desc-${action}`;

  return (
    /* Backdrop */
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-ink/40 px-4"
      aria-hidden="true"
      onClick={(e) => { if (e.target === e.currentTarget) onCancel(); }}
    >
      {/* Dialog */}
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={descId}
        className="w-full max-w-sm rounded-lg border border-ink/10 bg-white p-6 shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-4 flex items-start gap-3">
          <div
            className={`rounded-full p-2 ${action === "revoke" ? "bg-red-50 text-red-600" : "bg-orange-50 text-orange-600"}`}
            aria-hidden="true"
          >
            <AlertTriangle size={18} />
          </div>
          <div>
            <h2 id={titleId} className="font-display text-base font-semibold">
              {config.title}
            </h2>
            <p id={descId} className="mt-1 text-sm text-ink/50">
              {config.description}
            </p>
          </div>
        </div>

        <div className="mb-5">
          <label htmlFor="action-reason" className="mb-1 block text-xs font-medium text-ink/60">
            Motif {config.requireReason && <span className="text-red-500" aria-label="obligatoire">*</span>}
          </label>
          <textarea
            id="action-reason"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            rows={2}
            aria-required={config.requireReason}
            className="w-full rounded-md border border-ink/15 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-seal/40"
            placeholder="Décris la raison de cette action…"
          />
        </div>

        <div className="flex justify-end gap-2">
          <button
            type="button"
            onClick={onCancel}
            className="rounded-md border border-ink/15 px-4 py-2 text-sm hover:bg-ink/5"
          >
            Annuler
          </button>
          <button
            type="button"
            onClick={() => onConfirm(reason)}
            disabled={!canConfirm}
            className={`rounded-md px-4 py-2 text-sm text-white disabled:opacity-40 ${config.confirmClass}`}
          >
            {config.confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
