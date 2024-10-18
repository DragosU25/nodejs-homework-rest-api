const mongoose = require("mongoose");

const contactSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, "Set name for contact"],
  },
  email: {
    type: String,
    required: false, // Poate fi optional
  },
  phone: {
    type: String,
    required: false, // Poate fi optional
  },
  favorite: {
    type: Boolean,
    default: false,
  },
});

module.exports = mongoose.model("Contact", contactSchema);
