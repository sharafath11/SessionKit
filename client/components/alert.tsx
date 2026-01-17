"use client"

import { cn } from "@/lib/utils"

interface AlertProps {
  type?: "error" | "success" | "info"
  message: string
  onClose?: () => void
}

export function Alert({ type = "info", message, onClose }: AlertProps) {
  const styles = {
    error: "border-destructive/30 bg-destructive/10 text-destructive",
    success: "border-green-500/30 bg-green-500/10 text-green-700 dark:text-green-400",
    info: "border-blue-500/30 bg-blue-500/10 text-blue-700 dark:text-blue-400",
  }

  return (
    <div className={cn("rounded-md border px-4 py-3 text-sm", styles[type])}>
      <div className="flex items-center justify-between">
        <p>{message}</p>
        {onClose && (
          <button
            onClick={onClose}
            className="ml-2 opacity-70 hover:opacity-100 transition-opacity"
            aria-label="Close alert"
          >
            ×
          </button>
        )}
      </div>
    </div>
  )
}
