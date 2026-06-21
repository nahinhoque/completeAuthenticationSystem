# Complete Authentication System

A production-ready Node.js authentication backend built with Express, MongoDB, JWT, and OTP-based email verification. This project is designed to provide secure user registration, login, session management, and account verification flows for modern web applications.

## Overview

This API handles the core authentication lifecycle:

- User registration
- Email verification via OTP
- Secure login
- Access token and refresh token management
- Logout from current and all devices
- Protected user profile retrieval

## Features

- Secure password hashing with `bcrypt`
- JWT-based authentication for protected routes
- Refresh tokens stored securely in HTTP-only cookies
- OTP generation and email verification flow
- MongoDB-backed persistence with Mongoose
- Clean and modular project structure
- Easy setup for local development and deployment

## Tech Stack

- **Runtime:** Node.js
- **Framework:** Express.js
- **Database:** MongoDB with Mongoose
- **Authentication:** JWT, bcrypt
- **Email Delivery:** Nodemailer
- **Environment Management:** dotenv
- **Logging:** Morgan

## Project Structure

```bash
.
├── server.js
├── src/
│   ├── app.js
│   ├── config/
│   │   ├── config.js
│   │   └── database.js
│   ├── controllers/
│   │   └── auth.controller.js
│   ├── models/
│   │   ├── otp.model.js
│   │   ├── session.model.js
│   │   └── user.model.js
│   ├── routes/
│   │   └── auth.routes.js
│   ├── services/
│   │   └── email.service.js
│   └── utils/
│       └── utils.js
```

## Prerequisites

Before running the project, ensure you have:

- Node.js (v18 or newer recommended)
- MongoDB running locally or a reachable cloud database
- A valid email provider configuration for sending OTP emails

## Environment Variables

Create a `.env` file in the project root and configure the following variables:

```env
MONGO_URI=your_mongodb_connection_string
JWT_SECRET=your_jwt_secret_key

GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GOOGLE_REFRESH_TOKEN=your_google_refresh_token
GOOGLE_USER=your_google_email
```

## Installation

```bash
npm install
```

## Running the Application

Start the development server:

```bash
npm run dev
```

The app will be available at:

```bash
http://localhost:3000
```

## API Endpoints

### Authentication Routes

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Register a new user and send an OTP |
| POST | `/api/auth/login` | Authenticate a user |
| GET | `/api/auth/get-me` | Fetch current user profile |
| GET | `/api/auth/refresh-token` | Refresh the access token |
| GET | `/api/auth/logout` | Logout the current session |
| GET | `/api/auth/logout-all` | Logout all sessions for the user |
| GET | `/api/auth/verify-email` | Verify email using OTP |

## Example Request

### Register a new user

```http
POST /api/auth/register
Content-Type: application/json

{
  "username": "john",
  "email": "john@example.com",
  "password": "123456"
}
```

## Security Notes

- Refresh tokens are stored in secure HTTP-only cookies.
- Passwords are hashed before being persisted.
- OTP values are verified before account activation.
- Always keep your environment variables secure and private.

## License

This project is licensed under the ISC license.
