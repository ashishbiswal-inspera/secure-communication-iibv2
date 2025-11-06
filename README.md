# React-Go-Iceworm Monorepo

A monorepo project using Turborepo to manage a React + TypeScript frontend and a Go backend.

## Project Structure

```
.
├── frontend/          # React + Vite + TypeScript application
├── backend/           # Go API server
├── package.json       # Root workspace configuration
└── turbo.json         # Turborepo configuration
```

## Prerequisites

Before you begin, ensure you have the following installed:

- **Node.js** (v18 or higher) - [Download](https://nodejs.org/)
- **npm** (comes with Node.js)
- **Go** (v1.20 or higher) - [Download](https://golang.org/dl/)

## Getting Started

### 1. Install Dependencies

From the root directory, install all workspace dependencies:

```powershell
npm install
```

This will install:
- Turborepo and root-level dependencies
- Frontend dependencies (React, Vite, TypeScript, etc.)
- Backend package.json (minimal, just for turbo integration)

### 2. Start Development Servers

Run both frontend and backend simultaneously using Turborepo:

```powershell
npm run dev
```

This command starts:
- **Frontend** (Vite dev server): http://localhost:5173
- **Backend** (Go API server): http://localhost:9000

### 3. Access the Application

- Open your browser and navigate to **http://localhost:5173**
- The frontend will communicate with the backend API at **http://localhost:9000**

## Available Scripts

### Root Level

- `npm run dev` - Start both frontend and backend in parallel
- `npm run dev:frontend` - Start only the frontend
- `npm run dev:backend` - Start only the backend
- `npm run install:all` - Install/update all workspace dependencies

### Frontend (`cd frontend`)

- `npm run dev` - Start Vite dev server
- `npm run build` - Build for production
- `npm run preview` - Preview production build
- `npm run lint` - Run ESLint

### Backend (`cd backend`)

- `npm run dev` - Start Go server (alias for `go run main.go`)

## API Endpoints

The backend provides the following endpoints:

- **GET** `/api/get` - Returns a JSON response with status information
  ```json
  {
    "success": true,
    "message": "GET request successful",
    "data": { ... }
  }
  ```

- **POST** `/api/post` - Accepts JSON data and returns a response
  ```json
  // Request body
  {
    "name": "John Doe",
    "email": "john@example.com"
  }
  
  // Response
  {
    "success": true,
    "message": "Data received successfully",
    "data": { ... }
  }
  ```

## Technology Stack

### Frontend
- React 19
- TypeScript
- Vite
- React Router

### Backend
- Go
- Standard library HTTP server
- JSON API

### Monorepo
- Turborepo
- npm workspaces

## Development Notes

- **CORS**: The backend is configured to allow requests from `http://localhost:5173`
- **Hot Reload**: Both frontend (Vite HMR) and backend (manual restart) support development workflows
- **Ports**: 
  - Frontend: 5173
  - Backend: 9000

## Troubleshooting

### Port Already in Use

If you see an error that a port is already in use:

**Frontend (5173):**
```powershell
# Find and kill the process
netstat -ano | findstr :5173
taskkill /PID <PID> /F
```

**Backend (9000):**
```powershell
# Find and kill the process
netstat -ano | findstr :9000
taskkill /PID <PID> /F
```

### Go Not Found

Make sure Go is installed and in your PATH:
```powershell
go version
```

### npm Install Issues

Try clearing the cache and reinstalling:
```powershell
npm cache clean --force
rm -r node_modules
npm install
```

## License

MIT
