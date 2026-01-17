import { Request, Response, NextFunction } from "express";
import { sendResponse } from "../utils/response";
import { StatusCode } from "../enums/statusCode";
import { MESSAGES } from "../const/messages";
import { verifyAccessToken } from "../utils/jwtToken";
import { JsonWebTokenError, TokenExpiredError } from "jsonwebtoken";
import { TokenPayload } from "../types/authTypes";

export const authenticateToken = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const accessToken = req.cookies?.token;
  
  if (!accessToken) {
    console.log("[Middleware] No access token found");
    return sendResponse(res, StatusCode.UNAUTHORIZED, MESSAGES.AUTH.AUTH_REQUIRED, false);
  }

  try {
    const decoded = verifyAccessToken(accessToken) as TokenPayload;
    
    if (decoded?.id && decoded.role === 'user') {
      console.log("[Middleware] Access token valid for user:", decoded.id);
      return next();
    }

    console.log("[Middleware] Token valid but access denied for role:", decoded?.role);
    return sendResponse(res, StatusCode.FORBIDDEN, MESSAGES.COMMON.ACCESS_DENIED, false);
  } catch (error) {
    if (error instanceof TokenExpiredError) {
      console.log("[Middleware] Access token expired - returning 401");
      return sendResponse(res, StatusCode.UNAUTHORIZED, MESSAGES.AUTH.INVALID_TOKEN, false);
    }

    if (error instanceof JsonWebTokenError) {
      console.log("[Middleware] Invalid access token");
      return sendResponse(res, StatusCode.UNAUTHORIZED, MESSAGES.AUTH.INVALID_TOKEN, false);
    }

    console.error("[Middleware] Unexpected error:", error);
    return sendResponse(res, StatusCode.INTERNAL_SERVER_ERROR, MESSAGES.COMMON.SERVER_ERROR, false);
  }
};
