# NexusAuth - Production-Ready Full-Stack Authentication Boilerplate

**NexusAuth** is a premium, feature-rich authentication starter kit built with modern web technologies. It provides a robust foundation for building secure applications with features like JWT multi-token rotation, OTP verification, Google OAuth integration, and a clean hexagonal-inspired architecture.

## 🚀 Key Features

-   **Multi-Strategy Auth**: Support for Email/Password and Google OAuth.
-   **OTP Verification**: Secure registration flow with email-based OTP using Redis for TTL management.
-   **Security First**: 
    -   JWT Access & Refresh Token rotation.
    -   HTTP-only cookies to prevent XSS.
    -   Auto-refreshing tokens via Axios interceptors.
-   **Clean Architecture**:
    -   **Backend**: Controller-Service-Repository pattern with Dependency Injection (Tsyringe).
    -   **Frontend**: Next.js App Router with centralized API methods and custom hooks.
-   **Premium UI**: Sleek dashboard and auth pages built with Tailwind CSS and Radix UI components.
-   **Type Safety**: End-to-end TypeScript implementation.

---

## 🛠️ Tech Stack

### Backend
-   **Runtime**: Node.js
-   **Framework**: Express.js
-   **Language**: TypeScript
-   **Database**: MongoDB (Mongoose)
-   **Caching**: Redis (ioredis)
-   **DI Container**: Tsyringe
-   **Mailing**: Nodemailer

### Frontend
-   **Framework**: Next.js (App Router)
-   **State & Validation**: React Hook Form + Zod
-   **Styling**: Tailwind CSS + Radix UI
-   **HTTP Client**: Axios (with Interceptors)
-   **Notifications**: Sonner

---

## ⚙️ Getting Started

### Prerequisites
-   Node.js (v18+)
-   MongoDB (Running locally or Atlas)
-   Redis (Running locally or Upstash)

### 1. Clone the repository
```bash
git clone <your-repo-url>
cd NexusAuth
```

### 2. Backend Setup
```bash
cd server
npm install
```
Create a `.env` file in the `server` directory:
```env
PORT=5000
MONGODB_URI=your_mongodb_uri
REDIS_URL=your_redis_url
JWT_SECRET=your_access_token_secret
REFRESH_SECRET=your_refresh_token_secret
EMAIL_USER=your_gmail@gmail.com
EMAIL_PASS=your_app_password
GOOGLE_CLIENT_ID=your_google_client_id
```
Start the server:
```bash
npm run dev
```

### 3. Frontend Setup
```bash
cd ../client
npm install
```
Create a `.env.local` file in the `client` directory:
```env
NEXT_PUBLIC_BASEURL=http://localhost:5000
```
Start the frontend:
```bash
npm run dev
```

---

## 🏗️ Architecture Overview

### Backend Structure
-   `src/controller`: Handles HTTP requests and responses.
-   `src/services`: Contains business logic.
-   `src/repository`: Direct interaction with the database.
-   `src/core/di`: Dependency injection configuration.
-   `src/middleware`: Authentication and error handling logic.

### Frontend Structure
-   `app/(auth)`: Grouped routes for Login and Registration.
-   `app/dashboard`: Protected routes for logged-in users.
-   `services/`: Axios instance and API method definitions.

---

## 🔒 Security Implementation

-   **JWT Rotation**: When the access token expires (15m), the frontend interceptor automatically calls the refresh endpoint to get new tokens using the refresh token (7d) stored in a secure cookie.
-   **Logout**: Functional logout clears all cookies on both client and server sides.
-   **Silent Auth**: The dashboard fetches the user session on mount without visible loaders for a premium feel.

---

## 📄 License
This project is licensed under the ISC License.

---

**Developed with ❤️ by [Your Name/Github]**
