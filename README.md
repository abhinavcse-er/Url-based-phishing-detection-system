# PhishGuard — URL-based Phishing Detection

A responsive static frontend and a FastAPI backend that checks submitted URLs for common phishing indicators.

## Project structure

- `index.html`, `styles.css`, `app.js`: Netlify static frontend (repository root).
- `api-config.js`: public API base URL configuration.
- `server.py`: FastAPI analysis API.
- `requirements.txt`: Python dependencies.

## Deploy the frontend on Netlify

The site can be deployed from the repository root. No build command is required.

After deploying the API, edit `api-config.js` and set the public backend URL:
```js
window.PHISHING_API_BASE = "https://YOUR-BACKEND.onrender.com";
```
Commit the change; Netlify will redeploy automatically.

## Deploy the API on Render

1. Create a **Web Service** and connect this repository.
2. Runtime: Python.
3. Build command: `pip install -r requirements.txt`
4. Start command: `uvicorn server:app --host 0.0.0.0 --port $PORT`
5. Add environment variable `ALLOWED_ORIGINS` with your Netlify site origin, for example `https://detectphishing.netlify.app`.
6. Deploy, then test `https://YOUR-BACKEND.onrender.com/health`.

Free instances may sleep when idle, so the first request can take longer.

## Local development

```bash
pip install -r requirements.txt
uvicorn server:app --reload --port 5500
```

Set `window.PHISHING_API_BASE` in `api-config.js` to `http://127.0.0.1:5500` for local testing.

## Important limitations

The current implementation is a transparent heuristic ruleset, **not a trained machine-learning model** and not a live threat-intelligence lookup. A low score does not prove a URL is safe. It does not visit or fetch the submitted website. Use the result as an educational warning signal only.

## Author

Abhinav Kumar Mishra