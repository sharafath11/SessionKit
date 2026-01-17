import { GoogleAuthPayload, LoginPayload, RegisterPayload, ResendOtpPayload, VerifyOtpPayload } from "@/types/user/authTypes";
import { deleteRequest, getRequest, patchRequest, postRequest, putRequest } from "../api";

const get = getRequest;
const post = postRequest;
const patch = patchRequest;
const put = putRequest;
const del = deleteRequest;

export const userAuthMethods = {
  register: (payload: RegisterPayload) => post("/auth/signup", payload),
  verifyOtp: (payload: VerifyOtpPayload) => post("/auth/verify-otp", payload),
  resendOtp: (payload: ResendOtpPayload) => post("/auth/resend-otp", payload),
  login: (payload: LoginPayload) => post("/auth/login", payload),
  googleAuth: (payload: GoogleAuthPayload) => post("/auth/google", payload),
  me: () => get("/auth/me"),
  logout: () => post("/auth/logout", {}),
}
