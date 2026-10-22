
const express = require("express");
const app = require("./server/server");

app.get("/api/vercel-check", (req, res) => {
  res.json({ ok: true, service: "OrderFlow AI API" });
});

module.exports = app;
