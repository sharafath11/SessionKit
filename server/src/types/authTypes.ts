export interface ISignup {
    name: string,
    password: string,
  email: string,
  isVerified:boolean
}
export interface TokenPayload {
  id: string;
  role: string;
}