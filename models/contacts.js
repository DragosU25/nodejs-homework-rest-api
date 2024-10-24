const Contact = require("./contact");
const mongoose = require("mongoose");

async function listContacts(owner) {
  return await Contact.find({ owner });
}

async function getById(contactId, owner) {
  if (!mongoose.Types.ObjectId.isValid(contactId)) {
    throw new Error("Invalid ID format");
  }
  return Contact.findOne({ _id: contactId, owner });
}

async function removeContact(contactId, owner) {
  const result = await Contact.findOneAndRemove({ _id: contactId, owner });
  return result !== null;
}

async function addContact({ name, email, phone, owner }) {
  const newContact = new Contact({ name, email, phone, owner });
  return newContact.save();
}

async function updateContact(contactId, updateData, owner) {
  return Contact.findOneAndUpdate({ _id: contactId, owner }, updateData, {
    new: true,
  });
}

async function updateStatusContact(contactId, favorite, owner) {
  return Contact.findOneAndUpdate(
    { _id: contactId, owner },
    { favorite },
    { new: true }
  );
}

module.exports = {
  listContacts,
  getById,
  removeContact,
  addContact,
  updateContact,
  updateStatusContact,
};
