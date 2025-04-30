# 🔐 Secure Auth System

A full-stack authentication system built with modern web security practices, including JWT-based access and refresh tokens. This project provides secure signup, login, and logout functionalities for a typical user authentication flow.

## 🛡️ Security Practices

- Hashed passwords with **BCrypt**
- **Access/Refresh Token** split for better control
- **Refresh token rotation** and **invalidation** strategy
- **Role-based Authorization** support (RBAC-ready)
  
## ✨ Features

- ✅ User **Signup** with role selection
- 🔑 Secure **Login** using JWT (Access + Refresh Token)
- 🔁 Automatic token **refresh** mechanism
- 🚪 Proper **Logout** by revoking refresh tokens
- 🔒 Role-based access control (RBAC) ready
- ⚙️ Backend and frontend integration via secure REST APIs

## 🛠️ Tech Stack

- **Backend:** Java 17, Spring Boot, Spring Security, JWT
- **Database:H2
- **Tools:** Postman for testing, IntelliJ IDEA

## 🔄 Auth Flow

1. **Signup**
   - User registers with `username`, `password`, and a default or chosen `role`.
   - Passwords are hashed before storing in the DB.

2. **Login**
   - Validates credentials.
   - Issues:
     - **Access Token** (short-lived)
     - **Refresh Token** (stored in HttpOnly cookie or securely on the client)

3. **Accessing Protected Routes**
   - Client sends Access Token in Authorization header.
   - If Access Token is expired, a Refresh Token is used to issue a new one.

4. **Logout**
   - Refresh token is invalidated (e.g., deleted from DB or cache).

## 🧪 API Endpoints

| Endpoint        | Method | Description             |
|-----------------|--------|-------------------------|
| `/api/auth/signup` | POST   | Register new user        |
| `/api/auth/login`  | POST   | Authenticate user & return tokens |
| `/api/auth/refresh-token` | POST | Refresh access token |
| `/api/auth/logout` | POST   | Logout and invalidate session |

## 🚀 Getting Started

### Prerequisites

- Java 17
- H2 for testing

### Run Backend

```bash
./mvnw spring-boot:run



