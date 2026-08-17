import { useCallback, useState } from "react";
import { CheckCircle2, XCircle } from "lucide-react";
import { ToastContext } from "./toast-context";

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);

  const showToast = useCallback((message, type = "success") => {
    const id = Date.now() + Math.random();
    setToasts((prev) => [...prev, { id, message, type }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 3500);
  }, []);

  return (
    <ToastContext.Provider value={showToast}>
      {children}
      <div className="fixed bottom-5 right-5 z-[100] space-y-2">
        {toasts.map((t) => (
          <div
            key={t.id}
            className={`flex items-center gap-2 px-4 py-3 rounded-lg shadow-lg text-sm font-medium text-white animate-[slideIn_0.2s_ease-out] ${
              t.type === "success" ? "bg-seal-dark" : "bg-red-600"
            }`}
          >
            {t.type === "success" ? <CheckCircle2 size={16} /> : <XCircle size={16} />}
            {t.message}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

