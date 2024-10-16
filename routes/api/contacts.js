const express = require("express");
const router = express.Router();
const contactsModel = require("../../models/contacts");

// @ GET /api/contacts
router.get("/", async (req, res, next) => {
  try {
    const contacts = await contactsModel.listContacts();
    res.status(200).json(contacts);
  } catch (error) {
    next(error);
  }
});

// @ GET /api/contacts/:id
router.get("/:id", async (req, res, next) => {
  try {
    console.log(`Fetching contact with id: ${req.params.id}`);
    const contact = await contactsModel.getById(req.params.id);
    if (contact) {
      res.status(200).json(contact);
    } else {
      res.status(404).json({ message: "Not found" });
    }
  } catch (error) {
    next(error);
  }
});

// @ POST /api/contacts
router.post("/", async (req, res, next) => {
  try {
    const { name, email, phone } = req.body;

    if (!name) {
      return res.status(400).json({ message: "missing required name field" });
    } else if (!email) {
      return res.status(400).json({ message: "missing required email field" });
    } else if (!phone) {
      return res.status(400).json({ message: "missing required phone field" });
    }
    const newContact = await contactsModel.addContact({ name, email, phone });
    res.status(201).json(newContact);
  } catch (error) {
    next(error);
  }
});

// @ DELETE /api/contacts/:id
router.delete("/:id", async (req, res, next) => {
  try {
    const contact = await contactsModel.removeContact(req.params.id);
    if (contact) {
      res.status(200).json({ message: "contact deleted" });
    } else {
      res.status(404).json({ message: "Not found" });
    }
  } catch (error) {
    next(error);
  }
});

// @ PUT /api/contacts/:id
router.put("/:id", async (req, res, next) => {
  try {
    const updateData = req.body;
    if (Object.keys(updateData).length === 0) {
      return res.status(400).json({ message: "missing fields" });
    }
    const updatedContact = await contactsModel.updateContact(
      req.params.id,
      updateData
    );
    if (updatedContact) {
      res.status(200).json(updatedContact);
    } else {
      res.status(404).json({ message: "Not found" });
    }
  } catch (error) {
    next(error);
  }
});

module.exports = router;
