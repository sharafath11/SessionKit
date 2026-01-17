import { RegisterErrors, RegisterFormData } from "@/types/user/authTypes";
import { LoginErrors, LoginFormData } from "@/types/user/authTypes";

export const validateRegister = (data: RegisterFormData): RegisterErrors => {
  const errors: RegisterErrors = {};

  if (!data.fullName.trim()) {
    errors.fullName = "Full name is required";
  }

  if (!data.email.trim()) {
    errors.email = "Email is required";
  } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(data.email)) {
    errors.email = "Please enter a valid email";
  }

  if (!data.password) {
    errors.password = "Password is required";
  } else if (data.password.length < 8) {
    errors.password = "Password must be at least 8 characters";
  }

  if (!data.confirmPassword) {
    errors.confirmPassword = "Confirm password is required";
  } else if (data.password !== data.confirmPassword) {
    errors.confirmPassword = "Passwords do not match";
  }

  return errors;
};


export const validateLogin = (data: LoginFormData): LoginErrors => {
  const errors: LoginErrors = {};

  if (!data.email.trim()) {
    errors.email = "Email is required";
  } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(data.email)) {
    errors.email = "Please enter a valid email";
  }

  if (!data.password) {
    errors.password = "Password is required";
  }

  return errors;
};

export const validateOtp = (otp: string): string => {
  if (!otp || otp.trim().length === 0) {
    return "OTP is required";
  }
  if (otp.length !== 6) {
    return "OTP must be 6 digits";
  }
  if (!/^\d+$/.test(otp)) {
    return "OTP must contain only numbers";
  }
  return "";
};
