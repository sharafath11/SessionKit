import { AuthController } from "../../controller/auth.controller";
import { AuthRepository } from "../../repository/authRepository";
import { AuthService } from "../../services/auth.Service";
import { IAuthController } from "../interfaces/controllers/IAuth.Controller";
import { IAuthRepository } from "../interfaces/repository/IAuthRepository";
import { IAuthService } from "../interfaces/services/IAuthService";
import { TYPES } from "../types";
import { container } from "tsyringe";

container.registerSingleton<IAuthService>(TYPES.IAuthServices, AuthService);
container.registerSingleton<IAuthController>(TYPES.IAuthController, AuthController);
container.registerSingleton<IAuthRepository>(TYPES.IAuthRepository, AuthRepository);

export { container };
