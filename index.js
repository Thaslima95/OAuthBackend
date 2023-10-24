const express = require("express");
const cors = require("cors");
const axios = require("axios");
var bodyParser = require("body-parser");
const mysql = require("mysql");
var jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const app = express();

app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "aafiya.",
  database: "pyra_gateway",
});

db.connect(function (err) {
  if (err) throw err;
  console.log("Connected!");
});

app.post("/users/signup", async (req, res) => {
  if (req.body.googleAccessToken) {
    const { googleAccessToken } = req.body;

    await axios
      .get("https://www.googleapis.com/oauth2/v3/userinfo", {
        headers: {
          Authorization: `Bearer ${googleAccessToken}`,
        },
      })
      .then(async (response) => {
        const firstName = response.data.given_name;
        const lastName = response.data.family_name;
        const email = response.data.email;
        const picture = response.data.picture;
        console.log(response.data);

        const sql = "SELECT * FROM pyra_user WHERE email= ?";
        const value = [[email]];
        db.query(sql, [value], (err, data) => {
          if (err) throw err;
          if (data?.length > 0) {
            return res.status(400).json({ message: "User already exist!" });
          } else {
            const sql = "INSERT INTO pyra_user (email) VALUES ?";
            const value = [[email]];
            db.query(sql, [value], (err, data) => {
              if (err) throw err;

              const result = {
                verified: "true",
                email,
                firstName,
                lastName,
                profilePicture: picture,
              };
              const token = jwt.sign(
                {
                  email: email,
                  id: data.insertId,
                },
                "mysecret",
                { expiresIn: "1h" }
              );

              res.status(200).json({ result, token });
            });
          }
        });
      })
      .catch((err) => {
        res.status(400).json({ message: "Invalid access token!" });
      });
  } else {
    const { email, password, firstName, lastName } = req.body;
    const sql = "SELECT * FROM pyra_user WHERE email= ?";
    const value = [[email]];
    db.query(sql, [value], async (err, data) => {
      if (err) throw err;
      if (data?.length > 0) {
        return res.status(400).json({ message: "User already exist!" });
      } else {
        const hashedPassword = await bcrypt.hash(password, 12);
        const sql =
          "INSERT INTO pyra_user (email,firstName,lastName,password) VALUES ?";
        const value = [[email, firstName, lastName, hashedPassword]];
        db.query(sql, [value], (err, data) => {
          if (err) throw err;

          const result = {
            verified: "true",
            email,
            firstName,
            lastName,
          };
          const token = jwt.sign(
            {
              email: email,
              id: data.insertId,
            },
            "mysecret",
            { expiresIn: "1h" }
          );

          res.status(200).json({ result, token });
        });
      }
    });
  }
});

app.post("/users/signin", (req, res) => {
  console.log("signin");
  if (req.body.googleAccessToken) {
    // gogole-auth
    const { googleAccessToken } = req.body;
    console.log(req.body);
    axios
      .get("https://www.googleapis.com/oauth2/v3/userinfo", {
        headers: {
          Authorization: `Bearer ${googleAccessToken}`,
        },
      })
      .then(async (response) => {
        const firstName = response.data.given_name;
        const lastName = response.data.family_name;
        const email = response.data.email;
        const picture = response.data.picture;

        const sql = "SELECT * FROM pyra_user WHERE email=?";

        const value = [[email]];
        db.query(sql, [value], (err, data) => {
          if (err) throw err;
          if (data?.length > 0) {
            console.log(data);
            const result = {
              verified: "true",
              email,
              firstName,
              lastName,
              profilePicture: picture,
            };
            const token = jwt.sign(
              {
                email: email,
                id: data[0].id,
              },
              "mysecret",
              { expiresIn: "1h" }
            );

            res.status(200).json({ result, token });
          } else {
            return res.status(404).json({ message: "User don't exist!" });
          }
        });
      })
      .catch((err) => {
        res.status(400).json({ message: "Invalid access token!" });
      });
  } else {
    console.log("normal");
    const { email, password } = req.body;

    const sql = "SELECT * FROM pyra_user WHERE email= ?";
    value = [[email]];
    try {
      db.query(sql, [value], async (err, data) => {
        if (err) throw err;
        if (data?.length > 0) {
          console.log(data);
          const isPasswordOk = await bcrypt.compare(password, data[0].Password);
          if (!isPasswordOk)
            return res.status(400).json({ message: "Invalid credintials!" });
          const result = {
            verified: "true",
            email: data[0].email,
            firstName: data[0].firstName,
            lastName: data[0].lastName,
          };
          const token = jwt.sign(
            {
              email: data[0].email,
              id: data[0].id,
            },
            "mysecret",
            { expiresIn: "1h" }
          );

          res.status(200).json({ result: result, token });
        } else {
          return res.status(404).json({ message: "User don't exist!" });
        }
      });
    } catch (err) {
      console.log(err);
    }
  }
});

app.listen("8070", () => {
  console.log("Server is running!");
});
