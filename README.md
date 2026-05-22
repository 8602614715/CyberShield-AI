# CyberShield AI

CyberShield AI is a full-stack cyber fraud reporting and intelligence platform. It includes a FastAPI backend, a React + Vite frontend, MongoDB storage, authentication, report APIs, and machine-learning based fraud/spam analysis.

## Project Structure

```text
cyberFraud/
├── backend/
│   ├── app/
│   │   ├── main.py          # FastAPI application
│   │   ├── config.py        # Environment settings
│   │   ├── api/v1/          # API routes
│   │   ├── core/            # Security and shared logic
│   │   ├── db/              # MongoDB client and indexes
│   │   ├── ml/              # Model loading and inference
│   │   ├── schemas/         # Pydantic schemas
│   │   └── services/        # Business logic
│   ├── artifacts/models/    # Local ML artifacts
│   ├── scripts/             # Utility scripts
│   └── requirements.txt
├── frontend/                # React + Vite dashboard
├── .env.example             # Environment variable template
└── main.py                  # Legacy uvicorn shim
```

## Requirements

- Python 3.10+
- Node.js 18+
- MongoDB database

## Environment Setup

Copy the example environment file and update the values:

```powershell
Copy-Item .env.example .env
```

Required environment variables:

```env
MONGODB_URI=mongodb_url
MONGODB_DB_NAME=db_name
JWT_SECRET_KEY=your_secret_key
CORS_ORIGINS=http://127.0.0.1:5173,http://localhost:5173,vercel url
VT_API_KEY=virus_total_api_key
```

Keep `.env` private. Do not commit real passwords, API keys, tokens, or database URLs.

## Backend Setup

```powershell
cd backend
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Backend URL:

```text
http://127.0.0.1:8000
```

API docs:

```text
http://127.0.0.1:8000/docs
```

## Frontend Setup

Open a second terminal:

```powershell
cd frontend
npm install
npm run dev
```

Frontend URL:

```text
http://localhost:5173
```

Optional local API override:

```powershell
cd frontend
Copy-Item .env.example .env.local
```

## Deploy frontend (Vercel)

1. Deploy the backend on Render and copy its URL (e.g. `https://cybershield-api.onrender.com`).
2. In Render, set `CORS_ORIGINS` to your Vercel app URL (e.g. `https://your-app.vercel.app`).
3. [vercel.com](https://vercel.com) → **Add New Project** → import this repo.
4. **Root Directory**: `frontend`
5. **Build Command**: `npm run build` (default)
6. **Output Directory**: `dist`
7. **Environment variable**: `VITE_API_BASE_URL` = your Render backend URL (no trailing slash)
8. Deploy and test login at the Vercel URL.

## GitHub Push Notes

Do not push local virtual environments, installed packages, build folders, or large model binaries to GitHub.

These should stay out of Git:

```text
venv/
frontend/node_modules/
frontend/dist/
.env
__pycache__/
*.pyc
models/spam_roberta/model.safetensors
```

If GitHub rejects a push because large files were committed, remove them from Git tracking:

```powershell
git rm -r --cached venv
git rm --cached models/spam_roberta/model.safetensors
git add .gitignore
git commit -m "Remove large local files from git"
git push origin main
```

If the push is still rejected, the large files are already in old commits. Clean the history:

```powershell
pip install git-filter-repo
git filter-repo --path venv --path models/spam_roberta/model.safetensors --invert-paths
git push origin main --force
```

Use Git LFS if large model files must be stored with the repository.

## Notes

- Keep `.env.example` in the repository as a safe setup template.
- Keep `.env` only on your local machine.
- Recreate `venv/` locally whenever needed instead of pushing it.
