import nodemailer from "nodemailer";
import dotenv from "dotenv";
import { MailTemplates } from "../const/mailTemplates";

dotenv.config();

if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
  throw new Error("EMAIL_USER or EMAIL_PASS is missing in environment variables");
}

const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 465,
  secure: true,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

transporter.verify((error) => {
  if (error) {
    console.error("Email transporter error:", error);
  } else {
    console.log("Email transporter ready");
  }
});

export async function sendEmailOtp(
  email: string,
  otp: string
): Promise<void> {
  try {
    await transporter.sendMail({
      from: `"Learn Vista" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: MailTemplates.OTP.SUBJECT,
      text: MailTemplates.OTP.TEXT(otp),
      html: MailTemplates.OTP.HTML(otp),
    });

    console.log(`OTP email sent to ${email}`);
  } catch (error) {
    console.error("Failed to send OTP email", error);
    throw new Error("OTP_EMAIL_SEND_FAILED");
  }
}

export async function sendMentorStatusChangeEmail(
  email: string,
  status: string
): Promise<void> {
  try {
    await transporter.sendMail({
      from: `"Learn Vista" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: MailTemplates.MENTOR_STATUS_CHANGE.SUBJECT,
      text: MailTemplates.MENTOR_STATUS_CHANGE.TEXT(status),
      html: MailTemplates.MENTOR_STATUS_CHANGE.HTML(status),
    });

    console.log(`Mentor status email sent to ${email}`);
  } catch (error) {
    console.error("Failed to send mentor status email", error);
    throw new Error("MENTOR_STATUS_EMAIL_FAILED");
  }
}

export async function sendPasswordResetEmail(
  email: string,
  resetLink: string
): Promise<void> {
  try {
    await transporter.sendMail({
      from: `"Learn Vista" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: MailTemplates.PASSWORD_RESET.SUBJECT,
      text: MailTemplates.PASSWORD_RESET.TEXT(resetLink),
      html: MailTemplates.PASSWORD_RESET.HTML(resetLink),
    });

    console.log(`Password reset email sent to ${email}`);
  } catch (error) {
    console.error("Failed to send password reset email", error);
    throw new Error("PASSWORD_RESET_EMAIL_FAILED");
  }
}
