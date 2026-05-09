# NSL-KDD Flask Network Intrusion Detection App

A Flask web application for network intrusion detection using a trained machine learning model. Users can enter network connection features and receive a prediction of whether the connection is normal or an attack type such as DoS, Probe, R2L, or U2R.

## Live Demo

- https://web-production-137a8.up.railway.app/

## Features

- Flask backend with `/predict` endpoint for model inference
- Pre-loaded ML model artifacts in `model/artifacts.pkl`
- Predicts attack categories with confidence scores and descriptive risk details
- Sample attack payload routes for quick testing
- Deployable on Railway with `Procfile`

## Requirements

- Python 3.11+ recommended
- `flask`
- `gunicorn`
- `numpy`
- `pandas`
- `scikit-learn`
- `xgboost`
- `lightgbm`

## Installation

1. Clone the repository:

```bash
git clone <repo-url>
cd nsl_kdd_flask
```

2. Create and activate a Python virtual environment:

```bash
python -m venv venv
venv\Scripts\activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

## Running Locally

```bash
python app.py
```

Then open `http://127.0.0.1:5000` in your browser.

## Deployment

This project is ready for deployment on platforms like Railway. The existing `Procfile` indicates the Flask app should start with:

```text
gunicorn app:app
```

## Project Structure

- `app.py` — Flask application and prediction logic
- `requirements.txt` — Python dependencies
- `Procfile` — deployment entrypoint for Railway
- `templates/index.html` — frontend UI
- `static/` — static assets
- `model/` — serialized model artifacts

## Notes

The app uses a saved artifact file at `model/artifacts.pkl` containing the trained model, scaler, feature columns, and class labels.
