# PhishGuard AI

Offline, privacy-preserving, AI-powered email phishing detection and awareness system.

## Structure
- `backend/` — FastAPI, Python 3.11, modular microservices
- `frontend/` — React 18, TypeScript, Tailwind CSS
- `ai_modules/` — DistilBERT, LLM, RAG, explainability
- `database/` — MongoDB/PostgreSQL, ChromaDB
- `chrome_extension/` — Optional browser extension

## Features
- Real-time phishing detection (NLP, URL, header analysis)
- Explainable AI (token highlighting, reasoning)
- Offline LLM for explanations
- RAG-based knowledge retrieval
- Adaptive quizzes & gamification
- Dashboard UI
- Modular, offline, privacy-first

## Quick Start: Running Frontend & Backend

### Prerequisites
- **Python:** Version 3.8 to 3.11 (e.g., Python 3.10 recommended)
- **Node.js & npm:** Node.js 16+ and npm 8+

---

### 1. Backend Setup (FastAPI)

1. **Navigate to the project root:**
   ```
   cd path/to/Email_Phishing
   ```
2. **Create and activate a virtual environment (recommended):**
   - Windows:
     ```
     python -m venv venv
     venv\Scripts\activate
     ```
   - macOS/Linux:
     ```
     python3 -m venv venv
     source venv/bin/activate
     ```
3. **Install backend dependencies:**
   ```
   cd app
   pip install -r requirements.txt
   cd ..
   ```
4. **Set up environment variables:**
   - Copy the provided `.env` file to the project root and fill in your Google OAuth credentials:
     ```
     GOOGLE_CLIENT_ID=your-google-client-id
     GOOGLE_CLIENT_SECRET=your-google-client-secret
     ```
5. **Run the backend server:**
   - From the project root (where the `app` folder is):
     ```
     uvicorn app.main:app --reload
     ```
   - The backend will be available at: http://localhost:8000

---

### 2. Frontend Setup (React + Vite)

1. **Navigate to the frontend directory:**
   ```
   cd frontend
   ```
2. **Install frontend dependencies:**
   ```
   npm install
   ```
3. **Run the frontend development server:**
   ```
   npm run dev
   ```
   - The frontend will be available at: http://localhost:5173

---

### 3. Usage
- Open http://localhost:5173 in your browser to use the app.
- The frontend will communicate with the backend at http://localhost:8000.

---

### Troubleshooting
- Ensure Python and Node.js versions match the prerequisites.
- If you see `ModuleNotFoundError: No module named 'app'`, make sure you run uvicorn from the project root.
- If you have issues with environment variables, double-check your `.env` file and variable names.

---

**Summary:**
- Backend: FastAPI (Python 3.8–3.11), run with uvicorn
- Frontend: React (Vite), run with npm
- Set up .env for Google OAuth
- Run both servers and open the frontend in your browser
