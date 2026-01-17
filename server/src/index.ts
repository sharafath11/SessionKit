import "reflect-metadata";
import express from "express";
import "./core/di/container"; 
import authRoutes from "./routes/authRoutes";
import { connectDB } from "./config/database";
import dotenv from "dotenv";
import cors from "cors"
import cookieParser from "cookie-parser";

dotenv.config()
const app = express();
app.use(
  cors({
    origin: ["http://localhost:3000"], 
    credentials: true, 
  })
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser())
connectDB()
app.use("/api/auth", authRoutes);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
