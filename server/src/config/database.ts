import mongoose from "mongoose";
import { throwError } from "../utils/response";
import dotenv from "dotenv";
dotenv.config();
export const connectDB = async () => {
  try {
    const MONGO_URI = process.env.MONGO_URI;
    if (!MONGO_URI) throwError("MONGO_URI is not defined in .env");
    
    await mongoose.connect(MONGO_URI);
    console.log("MongoDB connected");
  } catch (err) {
    console.error(" MongoDB connection error:", err);
    process.exit(1);
  }
};
