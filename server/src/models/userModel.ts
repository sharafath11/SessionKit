import mongoose, { Model, Schema } from "mongoose";
import { IUser } from "../types/userTypes";

const userSchema: Schema<IUser> = new Schema({
    username: { type: String, required: true, },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true },
    isVerified: { type: Boolean, default: false },
    authProvider: { type: String, enum: ["local", "google"], default: "local" },
}, { timestamps: true })
export const UserModel :Model<IUser>=mongoose.model<IUser>("User",userSchema)
