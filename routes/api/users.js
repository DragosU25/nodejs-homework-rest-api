const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const gravatar = require("gravatar");
const multer = require("multer");
const { Jimp } = require("jimp");
const path = require("path");
const fs = require("fs").promises;
const auth = require("../../middlewares/auth");
const User = require("../../models/user");

const storage = multer.diskStorage({
  destination: "tmp/",
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${file.fieldname}-${Date.now()}${ext}`);
  },
});

const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png|gif/;
    const mimetype = filetypes.test(file.mimetype);
    const extname = filetypes.test(
      path.extname(file.originalname).toLowerCase()
    );

    if (mimetype && extname) {
      cb(null, true);
    } else {
      cb(new Error("Error: File type not supported!"), false);
    }
  },
});

// @ POST /users/signup
router.post("/signup", async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(409).json({ message: "Email in use" });
    }

    const hashedPassword = await bcrypt.hash(password, 8);
    const avatarURL = gravatar.url(email, { s: "250", d: "retro" }, true);
    const newUser = new User({ email, password: hashedPassword, avatarURL });
    await newUser.save();

    res.status(201).json({
      user: {
        email: newUser.email,
        subscription: newUser.subscription,
        avatarURL: newUser.avatarURL,
      },
    });
  } catch (error) {
    next(error);
  }
});

// @ POST /users/login
router.post("/login", async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: "Email or password is wrong" });
    }

    const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });
    user.token = token;
    await user.save();

    res.status(200).json({
      token,
      user: {
        email: user.email,
        subscription: user.subscription,
      },
    });
  } catch (error) {
    next(error);
  }
});

// @ GET /users/logout
router.get("/logout", auth, async (req, res, next) => {
  try {
    req.user.token = null;
    await req.user.save();
    res.status(204).send();
  } catch (error) {
    next(error);
  }
});

// @ GET /users/current
router.get("/current", auth, async (req, res, next) => {
  try {
    const { email, subscription } = req.user;
    res.status(200).json({ email, subscription });
  } catch (error) {
    next(error);
  }
});

// @ PATCH /users/avatars
router.patch(
  "/avatars",
  auth,
  upload.single("avatar"),
  async (req, res, next) => {
    try {
      if (!req.file) {
        return res.status(400).json({ message: "File not provided" });
      }

      const tempFilePath = req.file.path;
      const avatarName = `${req.user._id}_${Date.now()}${path.extname(
        req.file.originalname
      )}`;
      const avatarURL = `/avatars/${avatarName}`;
      const publicAvatarPath = path.join(
        __dirname,
        "../../public/avatars",
        avatarName
      );

      try {
        const image = await Jimp.read(tempFilePath);

        // Resize to 250x250 pixels
        // await image.resize(250, 250).writeAsync(publicAvatarPath);

        // Remove the temporary file
        await fs.unlink(tempFilePath);

        // Update user's avatar URL and save in the database
        req.user.avatarURL = avatarURL;
        await req.user.save();

        return res.status(200).json({ avatarURL });
      } catch (error) {
        console.error("Error during image processing:", error);
        return res.status(500).json({ message: "Image processing failed" });
      }
    } catch (error) {
      next(error);
    }
  }
);
module.exports = router;
