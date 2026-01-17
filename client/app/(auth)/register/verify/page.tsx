"use client"

import type React from "react"

import { useState, useEffect } from "react"
import { useRouter } from "next/navigation"
import { AuthCard } from "@/components/auth-card"
import { Button } from "@/components/button"
import { OTPInput } from "@/components/otp-input"
import { Alert } from "@/components/alert"
import { userAuthMethods } from "@/services/methods/userMethods"
import { showErrorToast, showSuccessToast } from "@/utils/toast"

export default function VerifyPage() {
  const router = useRouter()
  const [otp, setOtp] = useState("")
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState("")
  const [timeLeft, setTimeLeft] = useState(180)
  const [canResend, setCanResend] = useState(false)
  const [email, setEmail] = useState("")

  useEffect(() => {
    const storedEmail = sessionStorage.getItem("verifyEmail")
    if (!storedEmail) {
      showErrorToast("No email found. Please register again.")
      router.push("/register")
      return
    }
    setEmail(storedEmail)
  }, [router])

  useEffect(() => {
    if (timeLeft > 0) {
      const timer = setTimeout(() => setTimeLeft(timeLeft - 1), 1000)
      return () => clearTimeout(timer)
    } else if (timeLeft === 0) {
      setCanResend(true)
    }
  }, [timeLeft])

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault()

    if (otp.length !== 6) {
      setError("Please enter a valid 6-digit code")
      return
    }

    setIsLoading(true)
    setError("")

    const res = await userAuthMethods.verifyOtp({ email, otp })

    setIsLoading(false)

    if (!res || !res.ok) {
      setError(res?.msg || "Verification failed")
      showErrorToast(res?.msg || "Verification failed")
      return
    }

    showSuccessToast(res.msg || "Email verified successfully")
    sessionStorage.removeItem("verifyEmail")
    router.push("/login")
  }

  const handleResend = async () => {
    setTimeLeft(180)
    setCanResend(false)
    setError("")

    const res = await userAuthMethods.resendOtp({ email })

    if (!res || !res.ok) {
      showErrorToast(res?.msg || "Failed to resend OTP")
      return
    }

    showSuccessToast(res.msg || "OTP sent successfully")
  }

  return (
    <AuthCard title="Verify email" description="We've sent a code to your email address">
      <form onSubmit={handleVerify} className="space-y-6">
        <div className="rounded-md bg-secondary p-3 text-center">
          <p className="text-sm text-foreground font-medium">{email || "Loading..."}</p>
        </div>

        {error && <Alert type="error" message={error} onClose={() => setError("")} />}

        <OTPInput length={6} onChange={setOtp} error={error ? "" : undefined} />

        <Button
          type="submit"
          variant="primary"
          size="lg"
          className="w-full"
          isLoading={isLoading}
          disabled={otp.length !== 6}
        >
          Verify email
        </Button>

        <div className="flex items-center justify-between">
          <p className="text-xs text-muted-foreground">Didn't receive the code?</p>
          <button
            type="button"
            onClick={handleResend}
            disabled={!canResend}
            className="text-xs font-medium text-foreground hover:underline disabled:opacity-50 disabled:cursor-not-allowed transition-opacity"
          >
            {canResend ? "Resend code" : `Resend in ${timeLeft}s`}
          </button>
        </div>
      </form>
    </AuthCard>
  )
}
