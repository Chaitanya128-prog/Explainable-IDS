# Sentinel.AI - Explainable Real-Time Network IDS

An AI-powered Intrusion Detection System with a live frontend dashboard, FastAPI backend, and explainable threat analysis.

## Features

- Real-time packet capture
- ML-based intrusion detection
- Explainable AI (XAI)
- Backend + Frontend dashboard

## Tech Stack

- Python
- FastAPI
- Machine Learning models
- Network packet analysis
- React + Vite

## Push to GitHub

Run these commands from the project folder:

```bash
cd "C:\Users\Chaitanya\OneDrive\Desktop\Explainable ai ids"

git init
git add .
git commit -m "Initial commit: Sentinel.AI Explainable IDS"
git branch -M main
git remote add origin https://github.com/Chaitanya128-prog/Explainable-IDS.git
git push -u origin main
```

## Clone and Run

Anyone cloning the project can use:

```bash
git clone https://github.com/Chaitanya128-prog/Explainable-IDS.git
cd Explainable-IDS
pip install -r requirements.txt
cd frontend && npm install
```

Then run `START.bat` as Administrator.

## Manual Run

Backend:

```bash
python -m backend.main
```

Frontend:

```bash
cd frontend
npm run dev
```

## Project Structure

```text
Explainable ai ids/
|- backend/
|- frontend/
|- DATA/
|- app.py
|- main.py
|- model.py
|- explainer.py
|- live_capture.py
|- requirements.txt
|- START.bat
|- README.md
```
