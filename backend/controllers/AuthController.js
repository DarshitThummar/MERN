const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const db = require("../confing/Connection.js");

// Registration
exports.register = (req, res) => {
  const userData = {
    first_name: req.body.first_name,
    last_name: req.body.last_name,
    email: req.body.email,
    password: bcrypt.hashSync(req.body.password, 10),
    role_name: req.body.role_name, // 'customer' or 'admin'
  };

  const { first_name, last_name, email, password, role_name } = userData;

  db.query("SELECT email FROM users WHERE email = ?", [email], (err, rows) => {
    if (err) {
      console.error("Error checking if email exists:", err);
      res.status(500).json({ error: "Internal server error" });
      return;
    }

    if (rows.length > 0) {
      res.status(200).json({ message: "User already registered" });
    } else {
      // If email does not exist, proceed with user registration
      db.query(
        "INSERT INTO users (first_name, last_name, email, password, role_name) VALUES (?, ?, ?, ?, ?)",
        [first_name, last_name, email, password, role_name],
        (error, results, fields) => {
          if (error) {
            console.error("Error registering user: ", error);
            res.status(500).json({ error: "Internal server error" });
          } else {
            console.log("User registered successfully");
            var transporter = nodemailer.createTransport({
              service: "gmail",
              auth: {
                user: "youremail@gmail.com",
                pass: "yourpassword",
              },
            });

            var mailOptions = {
              from: "youremail@gmail.com",
              to: email,
              subject: "Email varification",
              text: "Email verify successfully",
            };

            transporter.sendMail(mailOptions, function (error, info) {
              if (error) {
                console.log(error);
              } else {
                console.log("Email sent: " + info.response);
              }
            });
            res.status(200).json({ message: "User registered successfully" });
          }
        }
      );
    }
  });
};

// Login
exports.login = (req, res) => {
  const { email, password } = req.body;

  db.query("SELECT * FROM users WHERE email = ?", [email], (err, rows) => {
    if (err) {
      console.error("Error selecting user:", err);
      res.status(500).json({ message: "Internal server error" });
      return;
    }

    if (rows.length === 0) {
      res.status(401).json({ message: "Email not found" });
      return;
    }

    const user = rows[0];

    if (user?.role_name !== "admin") {
      res.status(200).json({ message: "You are not allowed to login here!" });
      return;
    }
    // Compare the password with the hashed password stored in the database
    bcrypt.compare(password, user.password, (bcryptErr, bcryptResult) => {
      if (bcryptErr) {
        console.error("Error comparing passwords:", bcryptErr);
        res.status(500).json({ message: "Internal server error" });
        return;
      }

      if (!bcryptResult) {
        res.status(401).json({ message: "Incorrect password" });
        return;
      }

      // Password is correct, generate token or any other authentication logic here
      res.status(200).json({ message: "Login successful" });
    });
  });
};
