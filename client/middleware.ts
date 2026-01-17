import { NextResponse } from "next/server"
import type { NextRequest } from "next/server"

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl

  const token = request.cookies.get("token")?.value
  const refreshToken = request.cookies.get("refreshToken")?.value

  const isAuthenticated = Boolean(token || refreshToken)

  const isAuthPage =
    pathname === "/login" || pathname === "/register"

  const isPublicPage = pathname === "/"

  const isDashboard = pathname.startsWith("/dashboard")

  if (isAuthenticated) {
    if (isAuthPage || isPublicPage) {
      return NextResponse.redirect(
        new URL("/dashboard", request.url)
      )
    }
    return NextResponse.next()
  }

  if (!isAuthenticated && isDashboard) {
    return NextResponse.redirect(
      new URL("/login", request.url)
    )
  }

  return NextResponse.next()
}

export const config = {
  matcher: [
    "/",
    "/login",
    "/register",
    "/dashboard/:path*",
  ],
}
