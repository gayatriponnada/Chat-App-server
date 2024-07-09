import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { PrismaClient } from "@prisma/client";
import cors from "cors";

const app = express();
app.use(cors());
const prisma = new PrismaClient();
const port = 3000;
const salt = 10;

app.use(express.json());

app.post("/sign-up", async (req, res) => {
  const { email, username, gender, password } = req.body;
  const hashed = await bcrypt.hash(password, salt);
  if (!email) {
    return res.status(400).json({
      message: "Email should present",
    });
  }
  if (!username) {
    return res.status(400).json({
      message: "Username should present",
    });
  }
  if (!gender) {
    return res.status(400).json({
      message: "Gender should present",
    });
  }
  if (!password) {
    return res.status(400).json({
      message: "Password should present",
    });
  }

  const emailExists = await prisma.user.findFirst({
    where: { email },
  });
  if (emailExists) {
    return res.status(401).json({
      message: "Email Already exists",
    });
  }

  const newUser = await prisma.user.create({
    data: {
      email,
      username,
      gender,
      password: hashed,
    },
  });
  return res
    .status(201)
    .json({ message: "User created successfully", data: newUser });
});

app.get("/details", authenticationToken, async (req, res) => {
  const { email } = req.user;
  const user = await prisma.user.findFirst({
    where: { email },
    select: { email: true, username: true },
  });
  if (!user) return res.status(404).json({ message: "User not found" });
  return res.status(200).json(user);
});

app.get("/all-users", authenticationToken, async (req, res) => {
  const { id } = req.user;
  const users = await prisma.user.findMany({
    where: {
      NOT: {
        id,
      },
    },
    select: { email: true, username: true, gender: true },
  });
  return res.status(200).json({ users, user: req.user });
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await prisma.user.findFirst({
    where: { email: email },
  });
  if (!user) {
    return res.status(404).json({
      message: "User not exists",
    });
  }
  const verifyPassword = await bcrypt.compare(password, user.password);
  if (!verifyPassword) {
    return res.status(401).json({
      message: "Password invalid",
    });
  }

  const token = jwt.sign(
    { ...user, password: undefined },
    process.env.ACCESS_TOKEN_SECRET
  );
  res.json({ token, message: "Login success" });
});

function authenticationToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  console.log(authHeader);
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) {
    res.status(401).json({
      message: "Token undefined",
    });
  }
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Not Authorized" });
    req.user = user;
    console.log(user);
    next();
  });
}

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
