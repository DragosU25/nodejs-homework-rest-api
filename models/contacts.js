// models/contacts.js
const Contact = require("./contact");
const mongoose = require("mongoose");

async function listContacts() {
  return await Contact.find();
}

async function getById(contactId) {
  if (!mongoose.Types.ObjectId.isValid(contactId)) {
    throw new Error("Invalid ID format");
  }
  return Contact.findById(contactId);
}

async function removeContact(contactId) {
  const result = await Contact.findByIdAndRemove(contactId);
  return result !== null;
}

async function addContact({ name, email, phone }) {
  const newContact = new Contact({ name, email, phone });
  return newContact.save();
}

async function updateContact(contactId, updateData) {
  return Contact.findByIdAndUpdate(contactId, updateData, { new: true });
}

async function updateStatusContact(contactId, favorite) {
  return Contact.findByIdAndUpdate(contactId, { favorite }, { new: true });
}

module.exports = {
  listContacts,
  getById,
  removeContact,
  addContact,
  updateContact,
  updateStatusContact,
};
