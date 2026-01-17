import { Request, Response } from "express";

export interface IAuthController {
    login(req: Request, res: Response): Promise<void>
    signup(req: Request, res: Response): Promise<void>
    verifyOtp(req: Request, res: Response): Promise<void>
    resendOtp(req: Request, res: Response): Promise<void>
    googleAuth(req: Request, res: Response): Promise<void>
    getCurrentUser(req: Request, res: Response): Promise<void>
    logout(req: Request, res: Response): Promise<void>
    refeshToken(req: Request, res: Response): Promise<void>
}
