/* global google */
import { userAuthMethods } from "@/services/methods/userMethods";

declare global {
  interface Window {
    google?: any;
  }
}

export const loadGoogleScript = (): Promise<void> => {
  return new Promise((resolve, reject) => {
    if (window.google) {
      resolve();
      return;
    }

    const script = document.createElement("script");
    script.src = "https://accounts.google.com/gsi/client";
    script.async = true;
    script.defer = true;
    script.onload = () => resolve();
    script.onerror = () => reject(new Error("Failed to load Google script"));
    document.head.appendChild(script);
  });
};

export const initializeGoogleSignIn = (
  clientId: string,
  onSuccess: (token: string) => void,
  onError: (error: string) => void
) => {
  if (!window.google) {
    onError("Google script not loaded");
    return;
  }

  window.google.accounts.id.initialize({
    client_id: clientId,
    callback: (response: any) => {
      if (response.credential) {
        onSuccess(response.credential);
      } else {
        onError("Failed to get Google credential");
      }
    },
  });
};

export const renderGoogleButton = (elementId: string) => {
  if (!window.google) return;

  window.google.accounts.id.renderButton(
    document.getElementById(elementId),
    {
      theme: "outline",
      size: "large",
      width: "100%",
      text: "continue_with",
    }
  );
};

export const promptGoogleOneTap = () => {
  if (!window.google) return;
  window.google.accounts.id.prompt();
};
