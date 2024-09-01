const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");

const app = express();
app.use(bodyParser.json());

// Настройки базы данных
const pool = new Pool({
  user: "unhyefko5yqtlqpdways",
  host: "bpta3zmxtaxci29xnsm7-postgresql.services.clever-cloud.com",
  database: "bpta3zmxtaxci29xnsm7",
  password: "AjFvChSYulA04LEDQggskpgaS4cb5j",
  port: 50013,
});

// Роут для регистрации пользователя
app.post("/register", async (req, res) => {
  const { email, name, password } = req.body;

  try {
    // Проверка, существует ли пользователь
    const userExists = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );
    if (userExists.rows.length > 0) {
      return res.status(400).json({ message: "User already exists" });
    }

    // Хеширование пароля
    const hashedPassword = await bcrypt.hash(password, 10);

    // Сохранение пользователя в базе данных
    await pool.query(
      "INSERT INTO users (email, name, password) VALUES ($1, $2, $3)",
      [email, name, hashedPassword]
    );

    res.status(201).json({ message: "User created successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});

// Роут для логина пользователя
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    // Проверка пользователя в базе данных
    const user = await pool.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    if (user.rows.length === 0) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const validPassword = await bcrypt.compare(password, user.rows[0].password);
    if (!validPassword) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    // Генерация JWT токена
    const token = jwt.sign(
      { id: user.rows[0].id, email: user.rows[0].email },
      "your_secret_key",
      { expiresIn: "1h" }
    );

    res.json({ token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});

// Новый роут для получения всех пользователей
app.get("/users", async (req, res) => {
  try {
    const users = await pool.query("SELECT * FROM users");
    res.json(users.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});

// Запуск сервера
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
