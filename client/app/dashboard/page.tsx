"use client"

import { useEffect, useState } from "react"
import { useRouter } from "next/navigation"
import { Button } from "@/components/button"
import { userAuthMethods } from "@/services/methods/userMethods"
import { User } from "@/types/user/authTypes"
import { showSuccessToast, showErrorToast } from "@/utils/toast"

export default function DashboardPage() {
  const router = useRouter()
  const [user, setUser] = useState<User | null>(null)
  const [isLoading, setIsLoading] = useState(true)

  useEffect(() => {
    const fetchUser = async () => {
      const res = await userAuthMethods.me()
      if (res && res.ok) {
        setUser(res.data)
      } else {
        // me() usually handles 401 via axios interceptor 
        // which might redirect to /login
        // If not, we redirect here for safety
        router.push("/login")
      }
      setIsLoading(false)
    }

    fetchUser()
  }, [router])

  const handleLogout = async () => {
    const res = await userAuthMethods.logout()
    if (res && res.ok) {
      showSuccessToast("Logged out successfully")
      router.push("/login")
    } else {
      showErrorToast("Logout failed")
    }
  }

  if (isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <div className="animate-pulse space-y-4">
          <div className="h-12 w-12 rounded-full bg-accent mx-auto"></div>
          <div className="h-4 w-32 bg-accent rounded mx-auto"></div>
        </div>
      </div>
    )
  }

  if (!user) return null

  const getInitials = (name: string) => {
    return name
      .split(" ")
      .map((n) => n[0])
      .join("")
      .toUpperCase()
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-background p-4">
      <div className="w-full max-w-md">
        <div className="rounded-lg border border-border bg-card p-8 shadow-sm space-y-6">
          <div className="space-y-4">
            <div className="flex items-center gap-4">
              <div className="h-12 w-12 rounded-full bg-accent flex items-center justify-center text-accent-foreground font-semibold text-lg">
                {getInitials(user.name)}
              </div>
              <div className="overflow-hidden">
                <p className="font-medium text-card-foreground truncate">{user.name}</p>
                <p className="text-sm text-muted-foreground truncate">{user.email}</p>
              </div>
            </div>
          </div>

          <div className="rounded-md bg-secondary p-4 border border-border space-y-3">
            <div>
              <p className="text-xs uppercase tracking-wider text-muted-foreground font-semibold">Account Status</p>
              <div className="flex items-center gap-2 mt-1">
                <div className={`h-2 w-2 rounded-full ${user.isVerified ? 'bg-green-500' : 'bg-yellow-500'}`}></div>
                <p className="text-sm font-medium text-card-foreground">
                  {user.isVerified ? 'Verified' : 'Unverified'}
                </p>
              </div>
            </div>
            
            {user.authProvider && (
              <div>
                <p className="text-xs uppercase tracking-wider text-muted-foreground font-semibold">Login Method</p>
                <p className="text-sm font-medium text-card-foreground capitalize mt-1">
                  {user.authProvider}
                </p>
              </div>
            )}

            <div className="pt-2 border-t border-border">
              <h2 className="text-lg font-semibold text-card-foreground">Welcome back!</h2>
              <p className="text-sm text-muted-foreground mt-1">
                You are securely logged into your account.
              </p>
            </div>
          </div>

          <Button onClick={handleLogout} variant="secondary" size="lg" className="w-full">
            Log out
          </Button>
        </div>
      </div>
    </div>
  )
}
