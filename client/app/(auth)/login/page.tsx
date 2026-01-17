"use client"

import type React from "react"

import { useState, useEffect } from "react"
import { useRouter } from "next/navigation"
import Link from "next/link"
import { AuthCard } from "@/components/auth-card"
import { Button } from "@/components/button"
import { Input } from "@/components/input"
import { PasswordInput } from "@/components/password-input"
import { Divider } from "@/components/divider"
import { Alert } from "@/components/alert"
import { userAuthMethods } from "@/services/methods/userMethods"
import { validateLogin } from "@/lib/validation/auth.validation"
import { showErrorToast, showInfoToast, showSuccessToast } from "@/utils/toast"

export default function LoginPage() {
  const router = useRouter()
  const [formData, setFormData] = useState({
    email: "",
    password: "",
  })
  const [errors, setErrors] = useState<Record<string, string>>({})
  const [isLoading, setIsLoading] = useState(false)
  const [isGoogleLoading, setIsGoogleLoading] = useState(false)
  const [alertMessage, setAlertMessage] = useState<string>("")

  useEffect(() => {
    const loadGoogleScript = () => {
      const script = document.createElement("script")
      script.src = "https://accounts.google.com/gsi/client"
      script.async = true
      script.defer = true
      document.body.appendChild(script)

      script.onload = () => {
        if (window.google) {
          window.google.accounts.id.initialize({
            client_id: process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID || "",
            callback: handleGoogleResponse,
          })
        }
      }
    }

    loadGoogleScript()
  }, [])

  const handleGoogleResponse = async (response: any) => {
    if (!response.credential) {
      showErrorToast("Failed to get Google credential")
      return
    }

    setIsGoogleLoading(true)
    setAlertMessage("")

    const res = await userAuthMethods.googleAuth({
      googleToken: response.credential,
    })

    setIsGoogleLoading(false)

    if (!res || !res.ok) {
      const errorMsg = res?.msg || "Google authentication failed"
      setAlertMessage(errorMsg)
      showErrorToast(errorMsg)
      return
    }

    showSuccessToast(res.msg || "Login successful")
    router.push("/dashboard")
  }

  const handleGoogleSignIn = () => {
    if (window.google) {
      window.google.accounts.id.prompt()
    } else {
      showErrorToast("Google Sign-In not loaded")
    }
  }

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target
    setFormData((prev) => ({ ...prev, [name]: value }))
    if (errors[name]) {
      setErrors((prev) => ({ ...prev, [name]: "" }))
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    const validationErrors = validateLogin(formData)
    if (Object.keys(validationErrors).length > 0) {
      setErrors(validationErrors)
      return
    }

    setIsLoading(true)
    setAlertMessage("")

    const res = await userAuthMethods.login({
      email: formData.email,
      password: formData.password,
    })

    setIsLoading(false)

    if (!res || !res.ok) {
      const errorMsg = res?.msg || "Login failed"
      
      if (errorMsg.toLowerCase().includes("verify")) {
        setAlertMessage(errorMsg)
        showInfoToast(errorMsg)
        sessionStorage.setItem("verifyEmail", formData.email)
        router.push("/register/verify")
        return
      }

      setAlertMessage(errorMsg)
      showErrorToast(errorMsg)
      return
    }

    showSuccessToast(res.msg || "Login successful")
    router.push("/dashboard")
  }

  const isFormValid = formData.email.trim() && formData.password

  return (
    <AuthCard title="Sign in" description="Welcome back to your account">
      <form onSubmit={handleSubmit} className="space-y-4">
        {alertMessage && <Alert type="error" message={alertMessage} onClose={() => setAlertMessage("")} />}

        <Input
          label="Email Address"
          name="email"
          type="email"
          value={formData.email}
          onChange={handleChange}
          placeholder="you@example.com"
          error={errors.email}
        />

        <PasswordInput
          label="Password"
          name="password"
          value={formData.password}
          onChange={handleChange}
          placeholder="••••••••"
          error={errors.password}
        />

        <div className="flex justify-end">
          <Link href="/forgot-password" className="text-xs font-medium text-foreground hover:underline">
            Forgot password?
          </Link>
        </div>

        <Button
          type="submit"
          variant="primary"
          size="lg"
          className="w-full"
          disabled={!isFormValid}
          isLoading={isLoading}
        >
          Sign in
        </Button>

        <Divider text="or" />

        <Button type="button" variant="secondary" size="lg" className="w-full" onClick={handleGoogleSignIn} isLoading={isGoogleLoading}>
          <svg className="mr-2 h-4 w-4" viewBox="0 0 24 24" fill="currentColor">
            <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
            <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
            <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" />
            <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
          </svg>
          Continue with Google
        </Button>

        <p className="text-center text-sm text-muted-foreground">
          Don't have an account?{" "}
          <Link href="/register" className="font-medium text-foreground hover:underline">
            Create one
          </Link>
        </p>
      </form>
    </AuthCard>
  )
}
