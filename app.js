const express = require("express");
const mongoose = require("mongoose");
const multer = require("multer");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const path = require("path");
require("dotenv").config();

const User = require("./models/User");
const File = require("./models/File");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ✅ MongoDB Connection with logs
mongoose.set("strictQuery", true);
const defaultMongoUri = "mongodb://127.0.0.1:27017/secure-app";
const mongoUri = process.env.MONGO_URI?.trim() || defaultMongoUri;
const mongooseOptions = {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 10000,
};

const connectMongo = async () => {
  try {
    console.log(`Connecting to MongoDB: ${mongoUri}`);
    await mongoose.connect(mongoUri, mongooseOptions);
    console.log("MongoDB Connected");
  } catch (err) {
    console.error("MongoDB connection error:", err.message);
    if (mongoUri !== defaultMongoUri) {
      console.log("Attempting fallback to local MongoDB...");
      try {
        await mongoose.connect(defaultMongoUri, mongooseOptions);
        console.log("MongoDB Connected to local fallback");
        return;
      } catch (fallbackErr) {
        console.error("Local MongoDB fallback failed:", fallbackErr.message);
      }
    }
    console.error("Please verify your MONGO_URI in server/.env or install local MongoDB.");
    process.exit(1);
  }
};

// ✅ Multer Storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/");
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + "-" + file.originalname);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 * 1024 }
});

const authMiddleware = (req, res, next) => {
  const authHeader = req.header("Authorization");
  const token = authHeader?.replace("Bearer ", "");

  if (!token) return res.status(401).send("Unauthorized");

  try {
    const payload = jwt.verify(token, process.env.SECRET);
    req.user = payload;
    next();
  } catch (err) {
    res.status(401).send("Invalid or expired token");
  }
};
// ✅ File Type Configuration
const fileTypeOptions = {
  general: {
    label: "General file",
    extensions: [".pdf", ".doc", ".docx", ".txt", ".xlsx", ".csv"],
    mimeTypes: ["application/pdf", "application/msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "text/plain", "application/vnd.ms-excel", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "text/csv"],
    maxSize: 100 * 1024 * 1024, // 100MB
  },
  text: {
    label: "Text document",
    extensions: [".txt", ".md", ".doc", ".docx", ".pdf"],
    mimeTypes: ["text/plain", "text/markdown", "application/pdf", "application/msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"],
    maxSize: 10 * 1024 * 1024, // 10MB
  },
  image: {
    label: "Image",
    extensions: [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp"],
    mimeTypes: ["image/jpeg", "image/png", "image/gif", "image/bmp", "image/webp"],
    maxSize: 50 * 1024 * 1024, // 50MB
  },
  video: {
    label: "Video",
    extensions: [".mp4", ".avi", ".mov", ".mkv", ".webm", ".flv"],
    mimeTypes: ["video/mp4", "video/x-msvideo", "video/quicktime", "video/x-matroska", "video/webm", "video/x-flv"],
    maxSize: 500 * 1024 * 1024, // 500MB
  },
  archive: {
    label: "Archive",
    extensions: [".zip", ".rar", ".7z", ".tar", ".gz"],
    mimeTypes: ["application/zip", "application/x-rar-compressed", "application/x-7z-compressed", "application/x-tar", "application/gzip"],
    maxSize: 1024 * 1024 * 1024, // 1GB
  },
};

const validateFileType = (filename, mimeType, shareType) => {
  const typeConfig = fileTypeOptions[shareType] || fileTypeOptions.general;
  const fileExtension = path.extname(filename).toLowerCase();
  
  // Check extension
  const validExtension = typeConfig.extensions.some(ext => ext.toLowerCase() === fileExtension);
  if (!validExtension) {
    return {
      valid: false,
      error: `Invalid file extension. Allowed types for ${typeConfig.label}: ${typeConfig.extensions.join(", ")}`
    };
  }

  // Check MIME type
  const validMimeType = typeConfig.mimeTypes.some(type => mimeType.includes(type));
  if (!validMimeType) {
    return {
      valid: false,
      error: `Invalid MIME type for ${typeConfig.label}. Got: ${mimeType}`
    };
  }

  return { valid: true };
};
// ================= ROUTES =================

// ✅ Register
app.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).send("Name, email, and password are required");
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).send("Invalid email format");
    }

    // Trim and lowercase email
    const normalizedEmail = email.trim().toLowerCase();

    const existing = await User.findOne({ email: normalizedEmail });
    if (existing) return res.status(400).send("User already exists");

    const hash = await bcrypt.hash(password, 10);
    const newUser = new User({ name, email: normalizedEmail, password: hash });
    await newUser.save();

    res.send("Registered Successfully");
  } catch (err) {
    console.error("Registration Error:", err);
    if (err.code === 11000) {
      res.status(400).send("Email already registered");
    } else if (err.message.includes("validation failed")) {
      res.status(400).send("Invalid user data");
    } else {
      res.status(500).send("Error in Register: " + err.message);
    }
  }
});

// ✅ Login
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(404).send("User not found");

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(403).send("Wrong password");

    const token = jwt.sign({ email: user.email, name: user.name }, process.env.SECRET, { expiresIn: "1h" });

    res.json({ token, email: user.email });
  } catch (err) {
    res.status(500).send("Login Error");
  }
});

// ✅ Upload File
app.post("/upload", authMiddleware, upload.single("file"), async (req, res) => {
  try {
    const { visibility = "public", recipientEmail = "", shareType = "general", expiry = "60m", maxAccessCount } = req.body;

    if (!req.file) {
      return res.status(400).send("File is required");
    }

    // Validate file type based on shareType
    const typeConfig = fileTypeOptions[shareType] || fileTypeOptions.general;
    
    // Check file size
    if (req.file.size > typeConfig.maxSize) {
      const maxSizeMB = typeConfig.maxSize / (1024 * 1024);
      return res.status(400).send(`File size exceeds ${maxSizeMB}MB limit for ${typeConfig.label}`);
    }

    // Validate file type
    const validation = validateFileType(req.file.originalname, req.file.mimetype, shareType);
    if (!validation.valid) {
      return res.status(400).send(validation.error);
    }

    const recipients = [];
    if (visibility === "private") {
      if (!recipientEmail) {
        return res.status(400).send("Recipient email is required for private shares");
      }

      const recipient = await User.findOne({ email: recipientEmail });
      if (!recipient) {
        return res.status(404).send("Recipient user not found");
      }

      recipients.push(recipientEmail.toLowerCase());
    }

    const fileData = new File({
      filename: req.file.filename,
      originalName: req.file.originalname,
      owner: req.user.email,
      visibility,
      recipients,
      size: req.file.size,
      mimeType: req.file.mimetype,
      shareType,
      maxAccessCount: maxAccessCount ? parseInt(maxAccessCount) : null
    });

    await fileData.save();

    const tokenOptions = expiry && expiry !== "none" ? { expiresIn: expiry } : undefined;
    const token = tokenOptions
      ? jwt.sign({ id: fileData._id }, process.env.SECRET, tokenOptions)
      : jwt.sign({ id: fileData._id }, process.env.SECRET);

    const frontendUrl = process.env.FRONTEND_URL || "http://localhost:3000";
    const link = `${frontendUrl}/?token=${token}`;

    res.json({
      link
    });
  } catch (err) {
    console.error(err);
    res.status(500).send("Upload Error");
  }
});

// ✅ Get Files
app.get("/files", authMiddleware, async (req, res) => {
  try {
    const files = await File.find({ $or: [ { visibility: "public" }, { owner: req.user.email } ] });
    res.json(files);
  } catch (err) {
    res.status(500).send("Fetch Error");
  }
});

// ✅ Get File Info by Token
app.get("/file-info/:token", async (req, res) => {
  try {
    const data = jwt.verify(req.params.token, process.env.SECRET);
    const fileData = await File.findById(data.id);

    if (!fileData) {
      return res.status(404).send("File not found");
    }

    res.json({
      originalName: fileData.originalName,
      size: fileData.size,
      mimeType: fileData.mimeType,
      shareType: fileData.shareType,
      owner: fileData.owner,
      visibility: fileData.visibility,
      downloads: fileData.downloads,
      maxAccessCount: fileData.maxAccessCount,
      remainingAccesses: fileData.maxAccessCount !== null ? Math.max(0, fileData.maxAccessCount - fileData.downloads) : null
    });
  } catch (err) {
    res.status(403).send("Link expired or invalid");
  }
});

// ✅ Download File
app.get("/download/:token", async (req, res) => {
  try {
    const data = jwt.verify(req.params.token, process.env.SECRET);
    const fileData = await File.findById(data.id);

    if (!fileData) {
      return res.status(404).send("File not found");
    }

    if (fileData.maxAccessCount !== null && fileData.downloads >= fileData.maxAccessCount) {
      return res.status(403).send("Access limit exceeded. This link has reached its maximum access count.");
    }

    if (fileData.visibility === "private") {
      const requester = req.query.email?.toLowerCase();
      if (!requester || !fileData.recipients.includes(requester)) {
        return res.status(403).send("Private file link. Access denied.");
      }
    }

    await File.updateOne({ _id: fileData._id }, { $inc: { downloads: 1 } });

    const filePath = `uploads/${fileData.filename}`;
    const disposition = req.query.action === 'view' ? 'inline' : 'attachment';
    res.setHeader('Content-Disposition', `${disposition}; filename="${fileData.originalName}"`);
    res.sendFile(filePath, { root: __dirname });
  } catch (err) {
    res.status(403).send("Link expired or invalid");
  }
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

// ✅ Start Server
const PORT = process.env.PORT || 5000;

const startServer = async () => {
  await connectMongo();
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
};

startServer();