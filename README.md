# SessionKit – Production-Ready Full-Stack Authentication Boilerplate

**SessionKit** is a production-ready authentication starter kit built with modern web technologies. It provides a solid foundation for secure applications with features such as JWT session management, OTP verification, Google OAuth integration, and a clean, scalable architecture.

---

## Key Features

- **Multi-Strategy Authentication**
  - Email & Password
  - Google OAuth (Register & Login)

- **OTP Verification**
  - Email-based OTP during registration
  - Redis-backed OTP storage with TTL

- **Security First**
  - JWT Access & Refresh token rotation
  - HTTP-only cookies to prevent XSS
  - Automatic token refresh using Axios interceptors

- **Clean Architecture**
  - Backend: Controller–Service–Repository pattern with Dependency Injection (Tsyringe)
  - Frontend: Next.js App Router with centralized API methods and hooks

- **Modern UI**
  - Authentication pages and dashboard built with Tailwind CSS and Radix UI

- **Type Safety**
  - End-to-end TypeScript across frontend and backend

---

## Tech Stack

### Backend
- Node.js
- Express.js
- TypeScript
- MongoDB (Mongoose)
- Redis (ioredis)
- Tsyringe (Dependency Injection)
- Nodemailer

### Frontend
- Next.js (App Router)
- TypeScript
- Tailwind CSS
- Radix UI
- Axios (with interceptors)
- Sonner
- React Hook Form + Zod

---

## Getting Started

### Prerequisites
- Node.js (v18+)
- MongoDB (Local or Atlas)
- Redis (Local, Docker, or Upstash)

---

### 1. Clone the Repository

```bash
git clone https://github.com/sharafath11/SessionKit.git
cd SessionKit
2. Backend Setup
bash
Copy code
cd server
npm install
Create a .env file inside the server directory:

env
Copy code
PORT=5000
MONGODB_URI=your_mongodb_uri
REDIS_URL=your_redis_url
JWT_SECRET=your_access_token_secret
REFRESH_SECRET=your_refresh_token_secret
EMAIL_USER=your_gmail@gmail.com
EMAIL_PASS=your_gmail_app_password
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
Start the backend server:

bash
Copy code
npm run dev
3. Frontend Setup
bash
Copy code
cd ../client
npm install
Create a .env.local file inside the client directory:

env
Copy code
NEXT_PUBLIC_BASEURL=http://localhost:5000
Start the frontend:

bash
Copy code
npm run dev
Architecture Overview
Backend Structure
src/controller – HTTP request handling

src/services – Business logic

src/repository – Database access

src/core/di – Dependency Injection container

src/middleware – Authentication and error handling

src/utils – JWT, OTP, Redis, and mail utilities

Frontend Structure
app/(auth) – Login, Register, OTP verification

app/dashboard – Protected user dashboard

services/ – Axios instance and API methods

components/ – Reusable UI components

Security Implementation
JWT Rotation

Short-lived access token

Long-lived refresh token

Automatic refresh via Axios interceptor

Session Handling

Tokens stored in HTTP-only cookies

User session fetched via /auth/me

Logout

Clears access and refresh token cookies

Immediately invalidates the session

OTP Security

OTPs stored only in Redis

Automatic expiration using TTL

No OTP persistence in the database

License
This project is licensed under the ISC License.

Author
Sharafath
GitHub: https://github.com/sharafath11