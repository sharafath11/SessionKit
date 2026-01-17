import { Request } from "express";
import { throwError } from "./response";
import { MESSAGES } from "../const/messages";

export function validateBodyFields(req: Request, fields: string[]): void {
  if (!req.body) throwError(MESSAGES.COMMON.MISSING_FIELDS);
  const missingFields = fields.filter(field => !req.body[field]);
  if (missingFields.length > 0) throwError(MESSAGES.COMMON.MISSING_FIELDS);
}
