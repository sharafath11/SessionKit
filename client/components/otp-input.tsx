"use client"

import type React from "react"

import { useRef, useState } from "react"
import { cn } from "@/lib/utils"

interface OTPInputProps {
  length?: number
  onChange?: (value: string) => void
  error?: string
}

export function OTPInput({ length = 6, onChange, error }: OTPInputProps) {
  const [values, setValues] = useState<string[]>(Array(length).fill(""))
  const inputRefs = useRef<(HTMLInputElement | null)[]>([])

  const handleChange = (index: number, value: string) => {
    if (!/^\d*$/.test(value)) return

    const newValues = [...values]
    newValues[index] = value.slice(-1)
    setValues(newValues)

    // Auto-focus next input
    if (value && index < length - 1) {
      inputRefs.current[index + 1]?.focus()
    }

    // Call onChange with the full OTP
    onChange?.(newValues.join(""))
  }

  const handleKeyDown = (index: number, e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Backspace" && !values[index] && index > 0) {
      inputRefs.current[index - 1]?.focus()
    }
  }

  const handlePaste = (e: React.ClipboardEvent<HTMLInputElement>) => {
    e.preventDefault()
    const pastedData = e.clipboardData.getData("text").replace(/\D/g, "")
    const newValues = pastedData.split("").slice(0, length)

    while (newValues.length < length) {
      newValues.push("")
    }

    setValues(newValues)
    onChange?.(newValues.slice(0, length).join(""))

    // Focus last filled input or the next empty one
    const focusIndex = Math.min(
      newValues.findIndex((v) => v === ""),
      length - 1,
    )
    inputRefs.current[focusIndex]?.focus()
  }

  return (
    <div className="space-y-3">
      <div className="flex gap-3">
        {values.map((value, index) => (
          <input
            key={index}
            ref={(el) => {
              inputRefs.current[index] = el
            }}
            type="text"
            inputMode="numeric"
            maxLength={1}
            value={value}
            onChange={(e) => handleChange(index, e.target.value)}
            onKeyDown={(e) => handleKeyDown(index, e)}
            onPaste={handlePaste}
            className={cn(
              "h-12 w-12 rounded-md border border-border bg-input text-center text-lg font-semibold focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
              error && "border-destructive",
            )}
            aria-label={`OTP digit ${index + 1}`}
          />
        ))}
      </div>
      {error && <p className="text-xs text-destructive">{error}</p>}
    </div>
  )
}
