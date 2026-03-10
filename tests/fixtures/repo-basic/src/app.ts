// Main application entry point

import express from "express";

const app = express();

app.get("/", (req, res) => {
  res.json({ status: "ok", version: "1.0.0" });
});

app.get("/health", (req, res) => {
  res.json({ healthy: true });
});

export default app;
