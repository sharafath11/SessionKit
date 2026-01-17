import { Request, Response } from "express";
import { inject, injectable } from "tsyringe";
import { IAuthController } from "../core/interfaces/controllers/IAuth.Controller";
import { IAuthService } from "../core/interfaces/services/IAuthService";
import { TYPES } from "../core/types";
import { MESSAGES } from "../const/messages";
import { StatusCode } from "../enums/statusCode";
import {
  handleControllerError,
  sendResponse,
  throwError,
} from "../utils/response";
import { validateBodyFields } from "../utils/validateRequest";
import { clearTokens, decodeToken, refreshAccessToken, setTokensInCookies } from "../utils/jwtToken";

@injectable()
export class AuthController implements IAuthController {
  constructor(
    @inject(TYPES.IAuthServices) private  _authServices: IAuthService
  ) {}

  async login(req: Request, res: Response): Promise<void> {
    try {
      validateBodyFields(req, ["email", "password"])
      const { email, password } = req.body;
      if (!email || !password) throwError(MESSAGES.COMMON.MISSING_FIELDS,StatusCode.BAD_REQUEST);

      const result = await this._authServices.login(email, password);
      setTokensInCookies(res,result.tocken,result.refreshToken)
      sendResponse(
        res,
        StatusCode.OK,
        MESSAGES.AUTH.LOGIN_SUCCESS,
        true,
        result
      );
    } catch (error) {
      handleControllerError(res, error);
    }
  }

  async signup(req: Request, res: Response): Promise<void> {
    try {
      const { fullName, email, password } = req.body;
      validateBodyFields(req, ["fullName","email", "password"])
      await this._authServices.signup({
        name:fullName,
        email,
        password,
        isVerified:false
      });

      sendResponse(
        res,
        StatusCode.CREATED,
        MESSAGES.AUTH.REGISTRATION_SUCCESS,
        true,
        null
      );
    } catch (error) {
      handleControllerError(res, error);
    }
  }

  async verifyOtp(req: Request, res: Response): Promise<void> {
    try {
      validateBodyFields(req, ["email", "otp"]);
      const { email, otp } = req.body;

      await this._authServices.verifyOtp(email, otp);

      sendResponse(
        res,
        StatusCode.OK,
        MESSAGES.AUTH.VERIFICATION_SUCCESS,
        true,
        null
      );
    } catch (error) {
      handleControllerError(res, error);
    }
  }

  async resendOtp(req: Request, res: Response): Promise<void> {
    try {
      validateBodyFields(req, ["email"]);
      const { email } = req.body;

      await this._authServices.resendOtp(email);

      sendResponse(
        res,
        StatusCode.OK,
        MESSAGES.AUTH.OTP_SENT,
        true,
        null
      );
    } catch (error) {
      handleControllerError(res, error);
    }
  }

  async getCurrentUser(req: Request, res: Response): Promise<void> {
    try {
      const accessToken = req.cookies.token;
      const decoded = decodeToken(accessToken);
      if (!decoded) throwError(MESSAGES.AUTH.AUTH_REQUIRED, StatusCode.UNAUTHORIZED);
      
      const userId = decoded.id;
      const result = await this._authServices.getUser(userId);
      
      sendResponse(res, StatusCode.OK, MESSAGES.COMMON.SUCCESS, true, result);
    } catch (error) {
      handleControllerError(res, error, StatusCode.UNAUTHORIZED);
    }
  }

  async logout(req: Request, res: Response): Promise<void> {
    try {
      clearTokens(res);
      sendResponse(res, StatusCode.OK, MESSAGES.AUTH.LOGOUT_SUCCESS, true);
    } catch (error) {
      handleControllerError(res, error);
    }
  }

  async refeshToken(req: Request, res: Response): Promise<void> {
    try {
      console.log("[Controller] Refresh token endpoint hit");
      const refreshToken = req.cookies.refreshToken;
      
      if (!refreshToken) {
        console.log("[Controller] No refresh token in cookies");
        throwError("Refresh token not found", StatusCode.UNAUTHORIZED);
      }

      console.log("[Controller] Verifying refresh token and generating new tokens");
      const tokens = refreshAccessToken(refreshToken);
      
      if (!tokens) {
        console.log("[Controller] Refresh token invalid or expired");
        throwError(MESSAGES.AUTH.INVALID_TOKEN, StatusCode.UNAUTHORIZED);
      }

      console.log("[Controller] Setting new tokens in cookies");
      setTokensInCookies(res, tokens.accessToken, tokens.refreshToken);
      sendResponse(res, StatusCode.OK, "Token refreshed successfully", true);
    } catch (error) {
      console.error("[Controller] Refresh token error:", error);
      handleControllerError(res, error, StatusCode.UNAUTHORIZED);
    }
  }

  async googleAuth(req: Request, res: Response): Promise<void> {
    try {
      validateBodyFields(req, ["googleToken"]);
      const { googleToken } = req.body;

      const result = await this._authServices.googleAuth(googleToken);
      setTokensInCookies(res, result.tocken, result.refreshToken);
      
      sendResponse(
        res,
        StatusCode.OK,
        MESSAGES.AUTH.GOOGLE_AUTH_SUCCESS,
        true,
        result
      );
    } catch (error) {
      handleControllerError(res, error);
    }
  }
}
