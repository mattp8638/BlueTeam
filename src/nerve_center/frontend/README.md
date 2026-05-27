# BlueTeam Nerve Center Frontend

The Nerve Center is the "Single Pane of Glass" React Application for the BlueTeam platform. It provides high-performance data visualizations and real-time monitoring of fleet agents, SIEM alerts, and Incident Response cases.

## Core Features

*   **Real-time WebSocket Streaming:** The dashboard utilizes an active WebSocket connection (`ws://127.0.0.1:8000/ws/fleet`) to the FastAPI backend. It completely eliminates HTTP polling, meaning telemetry, alerts, and agent health metrics are pushed instantly to the UI as they happen.
*   **Interactive Visualizations:** Powered by `recharts` for seamless area and bar charting of threat metrics over time.
*   **Glassmorphism UI:** Built with custom Vanilla CSS and `lucide-react` icons for a premium, futuristic aesthetic.

## Setup & Running

This project is bundled with Vite.

```bash
# 1. Install dependencies
npm install

# 2. Run the development server
npm run dev &
```
*Note: Make sure the FastAPI backend is running first so the WebSocket connection does not immediately drop.*
