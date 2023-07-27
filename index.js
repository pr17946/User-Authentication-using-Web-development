const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, './.env') });
const bcrypt = require('bcrypt');
const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");


const app = express();
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));

mongoose.connect(process.env.MONGODB_PASS, { useNewUrlParser: true });

// Define the user schema for the database collection
const userSchema = new mongoose.Schema({
   name: String,
   dob: Date,
   email: String,
   username: String,
   password: String,
   phn: Number,
});


const User = mongoose.model("User", userSchema);

app.get("/", function (req, res) {
    res.sendFile(__dirname + "/public/HTML/index.html");
});
app.get("/register", function (req, res) {
    res.sendFile(__dirname + "/public/HTML/register.html");
});
app.get("/home", function (req, res) {
    res.sendFile(__dirname + "/public/HTML/register.html");
});

app.post("/register", async function (req, res) {
    const { name, dob, email, uname, pass1, pass2, phn } = req.body;
    // Check if password and password2 match
    if (pass1 !== pass2) {
        console.log("Passwords do not match");
        return res.status(400).send("Passwords do not match"); // Sending error response to the client
    }
    try {
        // Hash the user's password securely
        const hashedPassword = await bcrypt.hash(pass1, 10);
        const user = new User({
            name: name,
            dob: dob,
            email: email,
            username: uname,
            password: hashedPassword,
            phn: phn,
        });
        await user.save();
        console.log('Registered data saved Successfully!');
        res.redirect("/home");
    } catch (error) {
        console.error('Error occurred while saving data:', error);
        res.status(500).send("Internal Server Error");
    }
});

app.post("/login", async function (req, res) {
    const { uname, pwd } = req.body;
    try {
        // Find the user in the database by their username
        const foundUser = await User.findOne({ username: uname });
        if (foundUser) {
            // Compare the entered password with the hashed password in the database
            const passwordsMatch = await bcrypt.compare(pwd, foundUser.password);
            if (passwordsMatch) {
                // Passwords match, login successful
                res.redirect("/home");
            } else {
                console.log("Incorrect password");
                res.status(401).send("Incorrect password");
            }
        } else {
            console.log("User not found");
            res.status(401).send("User not found");
        }
    } catch (error) {
        console.error('Error occurred while querying data:', error);
        res.status(500).send("Internal Server Error");
    }
});

// Start the server and listen on port 3000
app.listen(3000, function () {
    console.log("Server is running on port 3000");
});
