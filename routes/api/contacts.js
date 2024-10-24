const express = require("express");
const router = express.Router();
const contactsModel = require("../../models/contacts");
const auth = require("../../middlewares/auth"); // Importă middleware-ul de autentificare

// @ GET /api/contacts
router.get("/", auth, async (req, res, next) => {
  try {
    const contacts = await contactsModel.listContacts(req.user._id);
    res.status(200).json(contacts);
  } catch (error) {
    next(error);
  }
});

// @ GET /api/contacts/:id
router.get("/:id", auth, async (req, res, next) => {
  try {
    const contact = await contactsModel.getById(req.params.id, req.user._id);
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
router.post("/", auth, async (req, res, next) => {
  try {
    const { name, email, phone } = req.body;
    const newContact = await contactsModel.addContact({
      name,
      email,
      phone,
      owner: req.user._id,
    });
    res.status(201).json(newContact);
  } catch (error) {
    next(error);
  }
});

// @ DELETE /api/contacts/:id
router.delete("/:id", auth, async (req, res, next) => {
  try {
    const contact = await contactsModel.removeContact(
      req.params.id,
      req.user._id
    );
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
router.put("/:id", auth, async (req, res, next) => {
  try {
    const updateData = req.body;
    const updatedContact = await contactsModel.updateContact(
      req.params.id,
      updateData,
      req.user._id
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

// @ PATCH /api/contacts/:id/favorite
router.patch("/:id/favorite", auth, async (req, res, next) => {
  try {
    const { favorite } = req.body;
    if (typeof favorite !== "boolean") {
      return res.status(400).json({ message: "missing field favorite" });
    }
    const updatedContact = await contactsModel.updateStatusContact(
      req.params.id,
      favorite,
      req.user._id
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
