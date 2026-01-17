import { IUser } from "../../../types/userTypes";
import { IBaseRepository } from "./IBaseRepository";

export interface IAuthRepository extends IBaseRepository <IUser,IUser>{
    
}