import { toast } from "sonner";

export function notifyError(
  message: string,
  action?: { label: string; onClick: () => void },
) {
  const text = message.trim();
  if (!text) return;
  toast.error(text, {
    id: text,
    duration: 8000,
    action: action
      ? { label: action.label, onClick: action.onClick }
      : undefined,
  });
}

export function notifyOk(message: string) {
  const text = message.trim();
  if (!text) return;
  toast.success(text, { id: text, duration: 4000 });
}
