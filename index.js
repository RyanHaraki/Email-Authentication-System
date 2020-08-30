const express = require("express");
const nodeMailer = require("nodemailer");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const crypto = require("crypto");
require("dotenv").config();

//bcrypt setup
const bcrypt = require("bcrypt");
const saltRounds = 10;

//Set up app & bodyparser
const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

//Set up nodemailer
var transporter = nodeMailer.createTransport({
  service: "Hotmail",
  auth: {
    user: process.env.HOST_EMAIL,
    pass: process.env.HOST_PASS,
  },
});

//Connect to DB
mongoose.connect("mongodb://localhost:27017/userDB", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

//make Mongoose work
mongoose.set("useNewUrlParser", true);
mongoose.set("useFindAndModify", false);
mongoose.set("useCreateIndex", true);
mongoose.set("useUnifiedTopology", true);

//Create a schema for user on signup
const userSchema = new mongoose.Schema({
  name: String,
  password: String,
  email: String,
  isVerified: { type: Boolean, default: false },
  verificationHash: String, //going to need to change this
});

//Model the User
const User = mongoose.model("User", userSchema);

app.get("/", (req, res) => {
  res.sendFile(__dirname + "/index.html");
});

//CREATE ACCOUNT

app.post("/", (req, res) => {
  //Set set variables
  const newUserName = req.body.userName;
  const newUserPass = req.body.userPass;
  const newUserEmail = req.body.userEmail;
  let token = crypto.randomBytes(64).toString("hex");

  bcrypt.hash(newUserPass, saltRounds, (err, hash) => {
    if (err) {
      res.send(err);
    } else {
      //create new user and user fields to input and save user in database
      let user = new User();
      user.name = newUserName;
      user.email = newUserEmail;
      user.password = hash;
      user.verificationHash = token;
      user.save();
    }
  });

  //Create the email
  var mailOptions = {
    from: process.env.HOST_EMAIL,
    to: newUserEmail,
    subject: "Please verify your email",
    //This should send the link with the verificationHash you put in the database, which directs back to the server. If the verificationHash is in the database, then authenticate.
    html: `
        <h5>Thanks for signing up! Please verify your email</h5>
        <a href="http://localhost:3000/verify/users/${token}">Click here to verify</a>
        `,
  };
  //Send the email to the user
  transporter.sendMail(mailOptions, function (error, info) {
    if (error) {
      console.log(error);
    } else {
      console.log("Email sent: " + info.response);
    }
  });

  //Redirect user to verify page
  res.redirect("/verify/email-sent");
});

//Email sent page
app.get("/verify/email-sent", (req, res) => {
  res.sendFile(__dirname + "/emailSent.html");
});

//User verification page
app.get("/verify/users/:verifiedId", (req, res) => {
  const verifiedId = req.params.verifiedId;
  //Check to see if the verificationHash the user was sent is the same as the one stored for them in the database
  User.findOne({ verificationHash: verifiedId }, (err, result) => {
    if (!err) {
      const notVerified = { isVerified: false };
      const verified = { isVerified: true };
      //Verify the user in the database
      User.findOneAndUpdate(notVerified, verified, (err) => {
        if (!err) {
          if (verified) {
            res.redirect("/success");
          } else {
            res.send(
              "There was an error verifying your account. Please try again."
            );
          }
        } else {
          res.send(500, { error: err });
        }
      });
    } else {
      res.send(err);
    }
    //Delete the verificationHash from the user in the database
    User.findOneAndUpdate(
      { verificationHash: verifiedId },
      { verificationHash: "" },
      (err) => {
        if (err) {
          console.log(err);
        }
      }
    );
  });
});

app.get("/login", (req, res) => {
  res.sendFile(__dirname + "/login.html");
});

app.post("/login", (req, res) => {
  //Get user fields
  const userEmail = req.body.loginEmail;
  const userPass = req.body.loginPassword;
  //Is user in database?
  User.findOne({ email: userEmail }, (err, user) => {
    if (!err) {
      //Compare password to database password
      bcrypt.compare(userPass, user.password, (err, result) => {
        //If user pass in database, check if verified & redirect to success
        if (result === true) {
          if (user.isVerified) {
            res.redirect("/success");
          } else {
            res.send(
              "You are not verified. Please check your email to access your account."
            );
          }
        } else {
          res.send("Incorrect password");
        }
      });
    } else {
      res.send(err);
    }
  });
});

app.get("/success", (req, res) => {
  res.sendFile(__dirname + "/success.html");
});

app.listen(3000, () => console.log("Server running on port 3000"));
