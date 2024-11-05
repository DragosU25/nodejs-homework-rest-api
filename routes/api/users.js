const express = require("express");
require("dotenv").config();
const router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const gravatar = require("gravatar");
const multer = require("multer");
const { Jimp } = require("jimp");
require("@jimp/png");
require("@jimp/jpeg");
require("@jimp/gif");
const path = require("path");
const fs = require("fs").promises;
const auth = require("../../middlewares/auth");
const User = require("../../models/user");
const { v4: uuidv4 } = require("uuid");
const sgMail = require("@sendgrid/mail");

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

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

const sendVerificationEmail = async (email, verificationToken, req) => {
  const verificationLink = `${req.protocol}://${req.get(
    "host"
  )}/api/users/verify/${verificationToken}`;
  const msg = {
    to: email, // Trimite la adresa utilizatorului
    from: process.env.SENDGRID_VERIFIED_SENDER,
    subject: "Verify your email address",
    text: `Please verify your email address by clicking on the following link: ${verificationLink}`,
    html: `<strong>Please verify your email address by clicking on the following link: <a href="${verificationLink}">${verificationLink}</a></strong>`,
  };
  await sgMail.send(msg);
};

router.post("/signup", async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(409).json({ message: "Email in use" });
    }

    const hashedPassword = await bcrypt.hash(password, 8);
    const avatarURL = gravatar.url(email, { s: "250", d: "retro" }, true);
    const verificationToken = uuidv4();
    const newUser = new User({
      email,
      password: hashedPassword,
      avatarURL,
      verificationToken,
      verify: false,
    });
    await newUser.save();

    // Trimite e-mailul de verificare
    await sendVerificationEmail(email, verificationToken, req);

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

router.get("/verify/:verificationToken", async (req, res, next) => {
  try {
    const { verificationToken } = req.params;
    const user = await User.findOne({ verificationToken });

    if (!user) {
      return res.status(404).json({ message: "Not Found" });
    }

    user.verificationToken = null;
    user.verify = true;
    await user.save();

    res.status(200).json({ message: "Verification successful" });
  } catch (error) {
    next(error);
  }
});

router.post("/verify", async (req, res, next) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: "missing required field email" });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (user.verify) {
      return res
        .status(400)
        .json({ message: "Verification has already been passed" });
    }

    const verificationToken = uuidv4();
    user.verificationToken = verificationToken;
    await user.save();

    await sendVerificationEmail(email, verificationToken, req);

    res.status(200).json({ message: "Verification email sent" });
  } catch (error) {
    next(error);
  }
});

router.post("/login", async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: "Email or password is wrong" });
    }

    if (!user.verify) {
      return res.status(403).json({ message: "Email not verified" });
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

router.get("/logout", auth, async (req, res, next) => {
  try {
    req.user.token = null;
    await req.user.save();
    res.status(204).send();
  } catch (error) {
    next(error);
  }
});

router.get("/current", auth, async (req, res, next) => {
  try {
    const { email, subscription } = req.user;
    res.status(200).json({ email, subscription });
  } catch (error) {
    next(error);
  }
});

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

        // Resize the image
        image.resize(250, 250);
        // Save the resized image to the public path
        await image.write(publicAvatarPath);

        // Delete the temporary file
        await fs.unlink(tempFilePath);

        // Update user's avatar URL and save
        req.user.avatarURL = avatarURL;
        await req.user.save();

        return res.status(200).json({ avatarURL });
      } catch (error) {
        return res.status(500).json({ message: "Image processing failed" });
      }
    } catch (error) {
      next(error);
    }
  }
);

module.exports = router;
