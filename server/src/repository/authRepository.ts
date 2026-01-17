import { IAuthRepository } from "../core/interfaces/repository/IAuthRepository";
import { UserModel } from "../models/userModel";
import { IUser } from "../types/userTypes";
import { BaseRepository } from "./baseRepository";

export class AuthRepository extends BaseRepository<IUser,IUser> implements IAuthRepository {
    constructor() {
        super(UserModel)
    }
}