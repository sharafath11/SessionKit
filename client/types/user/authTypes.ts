export type LoginFormData = {
  email: string;
  password: string;
};
export type LoginErrors = Partial<Record<keyof LoginFormData, string>>;
export type LoginPayload = {
  email: string;
  password: string;
};

export type RegisterFormData = {
  fullName: string;
  email: string;
  password: string;
  confirmPassword: string;
};

export type RegisterErrors = Partial<Record<keyof RegisterFormData, string>>;
export type RegisterPayload = {
  fullName: string;
  email: string;
  password: string;
};

export type VerifyOtpPayload = {
  email: string;
  otp: string;
};

export type ResendOtpPayload = {
  email: string;
};

export type GoogleAuthPayload = {
  googleToken: string;
};

export type User = {
  userId: string;
  name: string;
  email: string;
  isVerified: boolean;
  authProvider?: "local" | "google";
};
