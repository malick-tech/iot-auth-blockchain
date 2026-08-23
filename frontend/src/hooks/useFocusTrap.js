import { useEffect } from "react";

const FOCUSABLE = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(", ");

/**
 * Piège le focus à l'intérieur d'un élément référencé (modale, drawer…).
 * Gère aussi la fermeture via Escape.
 *
 * @param {React.RefObject} ref       – ref vers l'élément conteneur
 * @param {boolean}         active    – activer/désactiver le trap
 * @param {Function}        onEscape  – callback appelé quand Escape est pressé
 */
export function useFocusTrap(ref, active, onEscape) {
  useEffect(() => {
    if (!active || !ref.current) return;

    // Mémoriser l'élément actif avant d'ouvrir la modale pour le restaurer à la fermeture
    const previouslyFocused = document.activeElement;

    // Déplacer le focus sur le premier élément focalisable
    const focusable = ref.current.querySelectorAll(FOCUSABLE);
    if (focusable.length > 0) {
      focusable[0].focus();
    }

    function onKeyDown(e) {
      if (e.key === "Escape") {
        e.preventDefault();
        onEscape?.();
        return;
      }
      if (e.key !== "Tab") return;

      const elements = ref.current?.querySelectorAll(FOCUSABLE);
      if (!elements || elements.length === 0) return;

      const first = elements[0];
      const last  = elements[elements.length - 1];

      if (e.shiftKey) {
        if (document.activeElement === first) {
          e.preventDefault();
          last.focus();
        }
      } else {
        if (document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    }

    document.addEventListener("keydown", onKeyDown);

    return () => {
      document.removeEventListener("keydown", onKeyDown);
      // Restaurer le focus précédent à la fermeture
      if (previouslyFocused && typeof previouslyFocused.focus === "function") {
        previouslyFocused.focus();
      }
    };
  }, [active, ref, onEscape]);
}
