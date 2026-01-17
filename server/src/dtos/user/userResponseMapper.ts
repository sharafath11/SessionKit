import { IUser } from "../../types/userTypes";
import {IUserDto, IUserLoginDTO } from "./IUserDto";

export class UserResponseMapper {
    static toLoginUserResponse(user:IUser,tocken:string,refreshToken:string): IUserLoginDTO {
        return {
            userId:user._id.toString(), 
            name: user.username,
            email: user.email,
            tocken,
            refreshToken
        }
    }
    static toUserResponse(user: IUser): IUserDto{
        return {
            isVerified:user.isVerified,
            name: user.username,
            email: user.email,
            userId:user._id.toString(),
            authProvider: user.authProvider
        }
    }
} 