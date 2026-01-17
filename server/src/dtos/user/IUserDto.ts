export interface IUserDto {
    isVerified:boolean
    userId: string
    name: string
    email: string
    password?: string
    authProvider?: "local" | "google"
}
export interface IUserLoginDTO {
    userId: string
    name: string
    email: string
    tocken: string,
    refreshToken : string
}
