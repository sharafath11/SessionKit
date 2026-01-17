"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";

import { AuthCard } from "@/components/auth-card";
import { Button } from "@/components/button";
import { Input } from "@/components/input";
import { PasswordInput } from "@/components/password-input";
import { Divider } from "@/components/divider";
import { Alert } from "@/components/alert";


import { showErrorToast, showSuccessToast } from "@/utils/toast";
import { validateRegister } from "@/lib/validation/auth.validation";
import { userAuthMethods } from "@/services/methods/userMethods";

export default function RegisterPage() {
  const router = useRouter();

  const [formData, setFormData] = useState({
    fullName: "",
    email: "",
    password: "",
    confirmPassword: "",
  });

  const [errors, setErrors] = useState<Record<string, string>>({});
  const [isLoading, setIsLoading] = useState(false);
  const [isGoogleLoading, setIsGoogleLoading] = useState(false);
  const [alertMessage, setAlertMessage] = useState("");

  useEffect(() => {
    const loadGoogleScript = () => {
      const script = document.createElement("script");
      script.src = "https://accounts.google.com/gsi/client";
      script.async = true;
      script.defer = true;
      document.body.appendChild(script);

      script.onload = () => {
        if (window.google) {
          window.google.accounts.id.initialize({
            client_id: process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID || "",
            callback: handleGoogleResponse,
          });
        }
      };
    };

    loadGoogleScript();
  }, []);

  const handleGoogleResponse = async (response: any) => {
    if (!response.credential) {
      showErrorToast("Failed to get Google credential");
      return;
    }

    setIsGoogleLoading(true);
    setAlertMessage("");

    const res = await userAuthMethods.googleAuth({
      googleToken: response.credential,
    });

    setIsGoogleLoading(false);

    if (!res || !res.ok) {
      const errorMsg = res?.msg || "Google authentication failed";
      setAlertMessage(errorMsg);
      showErrorToast(errorMsg);
      return;
    }

    showSuccessToast(res.msg || "Registration successful");
    router.push("/dashboard");
  };

  const handleGoogleSignIn = () => {
    if (window.google) {
      window.google.accounts.id.prompt();
    } else {
      showErrorToast("Google Sign-In not loaded");
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;

    setFormData(prev => ({ ...prev, [name]: value }));

    if (errors[name]) {
      setErrors(prev => ({ ...prev, [name]: "" }));
    }
  };

 const handleSubmit = async (e: React.FormEvent) => {
  e.preventDefault();

  const validationErrors = validateRegister(formData);
  if (Object.keys(validationErrors).length > 0) {
    setErrors(validationErrors);
    return;
  }

  setIsLoading(true);

  const res = await userAuthMethods.register({
    fullName: formData.fullName,
    email: formData.email,
    password: formData.password,
  });

  setIsLoading(false);

  if (!res || !res.ok) {
    setAlertMessage(res?.msg || "Registration failed");
    showErrorToast(res?.msg || "Registration failed");
    return;
  }

  showSuccessToast(res.msg || "Registration successful");
  sessionStorage.setItem("verifyEmail", formData.email);
  router.push("/register/verify");
};


  const isFormValid =
    formData.fullName.trim() &&
    formData.email.trim() &&
    formData.password &&
    formData.confirmPassword &&
    formData.password === formData.confirmPassword &&
    Object.keys(errors).length === 0;

  return (
    <AuthCard title="Create account" description="Sign up to get started">
      <form onSubmit={handleSubmit} className="space-y-4">
        {alertMessage && (
          <Alert
            type="error"
            message={alertMessage}
            onClose={() => setAlertMessage("")}
          />
        )}

        <Input
          label="Full Name"
          name="fullName"
          value={formData.fullName}
          onChange={handleChange}
          placeholder="John Doe"
          error={errors.fullName}
        />

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

        <PasswordInput
          label="Confirm Password"
          name="confirmPassword"
          value={formData.confirmPassword}
          onChange={handleChange}
          placeholder="••••••••"
          error={errors.confirmPassword}
        />

        <Button
          type="submit"
          className="w-full"
          disabled={!isFormValid}
          isLoading={isLoading}
        >
          Create account
        </Button>

        <Divider text="or" />

        <Button type="button" variant="secondary" className="w-full" onClick={handleGoogleSignIn} isLoading={isGoogleLoading}>
          Continue with Google
        </Button>

        <p className="text-center text-sm text-muted-foreground">
          Already have an account?{" "}
          <Link href="/login" className="font-medium hover:underline">
            Sign in
          </Link>
        </p>
      </form>
    </AuthCard>
  );
}
