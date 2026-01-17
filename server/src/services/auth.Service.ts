import { inject, injectable } from "tsyringe";
import bcrypt from "bcrypt";
import { OAuth2Client } from "google-auth-library";
import { IAuthService } from "../core/interfaces/services/IAuthService";
import { IAuthRepository } from "../core/interfaces/repository/IAuthRepository";
import { TYPES } from "../core/types";
import { throwError } from "../utils/response";
import { MESSAGES } from "../const/messages";
import { UserResponseMapper } from "../dtos/user/userResponseMapper";
import { IUserDto, IUserLoginDTO } from "../dtos/user/IUserDto";

import { generateAccessToken, generateRefreshToken } from "../lib/jwtToken";
import { generateOtp, OTP_TTL_SECONDS } from "../utils/otp.util";
import { redis } from "../utils/redis";
import { sendEmailOtp } from "../utils/mail.util";

@injectable()
export class AuthService implements IAuthService {
  constructor(
    @inject(TYPES.IAuthRepository)
    private  _authRepo: IAuthRepository
  ) {}

  async login(email: string, password: string): Promise<IUserLoginDTO> {
    const user = await this._authRepo.findOne({ email });
    if (!user) throwError(MESSAGES.AUTH.NOT_FOUND);

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) throwError(MESSAGES.AUTH.INVALID_CREDENTIALS);

    if (!user.isVerified) throwError(MESSAGES.AUTH.AUTH_REQUIRED);

    const token = generateAccessToken(user._id as unknown as string,"user");
    const refreshToken = generateRefreshToken(user._id as unknown as string,"user");
    return UserResponseMapper.toLoginUserResponse(user,token,refreshToken);
  }

async signup(data: { name: string; email: string; password: string }):Promise<void> {
  const existingUser = await this._authRepo.findOne({ email: data.email });
  if (existingUser?.isVerified) {
    throwError(MESSAGES.AUTH.USER_ALREADY_EXISTS);
  }
  let user;
  const hashedPassword = await bcrypt.hash(data.password, 10);
  if (existingUser && !existingUser.isVerified) {
    user = existingUser;
  } 
  else {
    user = await this._authRepo.create({
      username: data.name,
      email: data.email,
      password: hashedPassword,
      isVerified: false,
    });
  }

  if (!user) {
    throwError(MESSAGES.COMMON.SERVER_ERROR);
  }

  const otp = generateOtp();
  const redisKey = `otp:register:${user._id}`;
  const existingOtp = await redis.get(redisKey);
  if (existingOtp) {
    throwError(MESSAGES.AUTH.OTP_ALREADY_SENT);
  }

  await redis.set(redisKey, otp, "EX", OTP_TTL_SECONDS);
  await sendEmailOtp(user.email, otp);

}


  async verifyOtp(email: string, otp: string): Promise<void> {
    const user = await this._authRepo.findOne({ email });
    if (!user) throwError(MESSAGES.AUTH.NOT_FOUND);
    
    const redisKey = `otp:register:${user._id}`;
    const storedOtp = await redis.get(redisKey);
    
    if (!storedOtp) throwError(MESSAGES.AUTH.OTP_EXPIRED);
    if (storedOtp !== otp) throwError(MESSAGES.AUTH.INVALID_OTP);
    
    await this._authRepo.update(user._id as unknown as string, {
      isVerified: true,
    });
    
    await redis.del(redisKey);
  }

  async resendOtp(email: string): Promise<void> {
    const user = await this._authRepo.findOne({ email });
    if (!user) throwError(MESSAGES.AUTH.NOT_FOUND);
    if (user.isVerified) throwError(MESSAGES.AUTH.ALREADY_REGISTERED);
    
    const otp = generateOtp();
    const redisKey = `otp:register:${email}`;
    
    await redis.set(redisKey, otp, "EX", OTP_TTL_SECONDS);
    await sendEmailOtp(user.email, otp);
  }

  async getUser(id: string): Promise<IUserDto> {
    const user = await this._authRepo.findById(id);
    if (!user) throwError(MESSAGES.COMMON.SERVER_ERROR);
    return  UserResponseMapper.toUserResponse(user)
  }

  async googleAuth(googleToken: string): Promise<IUserLoginDTO> {
    try {
      const clientId = process.env.GOOGLE_CLIENT_ID;
      if (!clientId) throwError("Google Client ID not configured");

      const client = new OAuth2Client(clientId);
      
      const ticket = await client.verifyIdToken({
        idToken: googleToken,
        audience: clientId,
      });

      const payload = ticket.getPayload();
      if (!payload || !payload.email) {
        throwError(MESSAGES.AUTH.INVALID_TOKEN);
      }

      const email = payload.email;
      const name = payload.name || email.split("@")[0];

      let user = await this._authRepo.findOne({ email });

      if (user) {
        const token = generateAccessToken(user._id as unknown as string, "user");
        const refreshToken = generateRefreshToken(user._id as unknown as string, "user");
        return UserResponseMapper.toLoginUserResponse(user, token, refreshToken);
      }

      const randomPassword = await bcrypt.hash(Math.random().toString(36), 10);
      user = await this._authRepo.create({
        username: name,
        email: email,
        password: randomPassword,
        isVerified: true,
        authProvider: "google",
      });

      if (!user) throwError(MESSAGES.AUTH.USER_UPDATE_FAILED);

      const token = generateAccessToken(user._id as unknown as string, "user");
      const refreshToken = generateRefreshToken(user._id as unknown as string, "user");
      return UserResponseMapper.toLoginUserResponse(user, token, refreshToken);
    } catch (error: any) {
      if (error.message && !error.message.includes("Google")) {
        throw error;
      }
      throwError(MESSAGES.AUTH.INVALID_GOOGLE_CREDENTIALS);
    }
  }
}
