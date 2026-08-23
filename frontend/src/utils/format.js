/**
 * Utilitaires de formatage partagés entre App, LogsPage et DeviceDetailPanel.
 * Centralise les fonctions pures pour éviter la duplication.
 */

export function formatDate(value) {
  if (!value) return "-";
  return new Date(value).toLocaleString("fr-FR", {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

export function formatDateTime(value) {
  if (!value) return "-";
  return new Date(value).toLocaleString("fr-FR", {
    dateStyle: "medium",
    timeStyle: "medium",
  });
}

export function truncateDid(did) {
  if (!did) return "-";
  const prefix = "did:algo:";
  const key = did.startsWith(prefix) ? did.slice(prefix.length) : did;
  return `${prefix}${key.slice(0, 12)}...${key.slice(-10)}`;
}

export function txUrl(txId) {
  return txId
    ? `https://lora.algokit.io/localnet/transaction/${encodeURIComponent(txId)}`
    : null;
}
