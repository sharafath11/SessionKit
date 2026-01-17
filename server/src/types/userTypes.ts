import { Document, Types } from "mongoose";

export interface IUser extends Document {
  _id: Types.ObjectId;  
  username: string;
  email: string;
  isVerified: boolean;
  password: string;
  authProvider?: "local" | "google";
}
