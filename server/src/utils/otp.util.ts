import { redis } from "./redis";

export const OTP_TTL_SECONDS = 3 * 60; 

export const generateOtp = (): string => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

export const storeOtp = async (
  purpose: "register" | "reset",
  identifier: string,
  otp: string
): Promise<void> => {
  const key = `otp:${purpose}:${identifier}`;
  await redis.set(key, otp, "EX", OTP_TTL_SECONDS);
};

export const verifyOtp = async (
  purpose: "register" | "reset",
  identifier: string,
  otp: string
): Promise<boolean> => {
  const key = `otp:${purpose}:${identifier}`;
  const storedOtp = await redis.get(key);

  if (!storedOtp) return false;
  if (storedOtp !== otp) return false;

  await redis.del(key);
  return true;
};
