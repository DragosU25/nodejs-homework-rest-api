const express = require("express");
const logger = require("morgan");
const cors = require("cors");

const contactsRouter = require("./routes/api/contacts");

const app = express();

app.use(logger("dev"));
app.use(cors());
app.use(express.json());

app.use("/api/contacts", contactsRouter);

// catch 404 and forward to error handler
app.use((req, res, next) => {
  res.status(404).json({ message: "Not found" });
});

// error handler
app.use((err, req, res, next) => {
  res.status(err.status || 500).json({ message: err.message });
});

module.exports = app;
