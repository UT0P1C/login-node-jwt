// dependencies
require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const validator = require("email-validator");

//express init
const app = express();

//config json express

app.use(express.json());

//models

const User = require("./models/User");

//routes

//open route - homepage
app.get("/", (req, res) => {
	res.status(200).json({message: "Hello World"})
});

//private route - user dashboard

app.get("/user/:id", checkToken, async(req, res) => {
	//get the user id
	const id = req.params.id;

	//check if the id exists
	
	const user = await User.findById(id, '-password');

	if(!user){
		return res.status(404).json({error: "user not found"});
	}

	return res.status(200).json({user})

});

//middleware to private route

function checkToken(req, res, next){
	const authHeader = req.headers['authorization'];
	const token = authHeader && authHeader.split(' ')[1];

	if(!token){
		return res.status(401).json({error: "unauthorized access"});
	}

	try{
		const secret = process.env.SECRET;

		jwt.verify(token, secret);

		next();
		
	}catch(err){
		return res.status(403).json({error: "Invalid Token"});
	}
}

//mongoDB connect

const db_user = process.env.USER_DB;

const db_pass = process.env.USER_PASS;

mongoose
		.connect(`mongodb+srv://${db_user}:${db_pass}@node-jwt.gypmc.mongodb.net/?retryWrites=true&w=majority`)
		.then(() => {
			app.listen(3000);
			console.log("OK!")
		})
		.catch((err) => {
			console.log(err);
		});

//creating user

app.post("/register",async(req, res) => {
	const {name, email, password, confirmPassword} = req.body;

	//validations

	if(!name){
		return res.status(422).json({error: "name is not valid"});
	}

	if(!email | validator.validate(email) == false){
		return res.status(422).json({error: "email is not valid"});
	}

	if(!password | password !== confirmPassword){
		return res.status(422).json({error: "the passwords does'nt match or don't exist"});
	}

	//check if user email is already registered

	const alreadyRegistered = await User.findOne({email: email});

	if (alreadyRegistered){
		return res.status(422).json({error: "email already registered!"})
	}


	//encrypt password

	const salt = await bcrypt.genSalt(12);

	const hashedPass = await bcrypt.hash(password, salt);

	//create user

	const user = new User({
		name,
		email,
		password: hashedPass,
	});

	try{
		//save user in database
		await user.save();
		
		return res.status(201).json({message: "User registered successfully!"})

	}catch(err){
		console.log(err);
		return res.status(500).json({error: "error on register"});
	}
});


//login

app.post("/login", async(req, res) => {
	//get email and pass from req
	const {email, password} = req.body;

	if(!email){
		return res.status(422).json({error: "email is not valid"});
	}

	if(!password){
		return res.status(422).json({error: "missing password"});
	}

	//check if email is registered

	const user = await User.findOne({email: email});

	if(!user){
		return res.status(404).json({error: "user not found!"});
	}

	//check if password match

	const validPass = await bcrypt.compare(password, user.password);

	if(user && !validPass){
		return res.status(422).json({error: "invalid password, try again!"});
	}

	//authenticate and token generator

	try{
		const secret = process.env.SECRET;
		const token = jwt.sign({
			id: user._id
		}, secret)

		return res.status(201).json({message: "Authenticated successfuly!", token});
	}catch(err){
		console.log(err);
		return res.status(500).json({error: "error on login"});
	}

})
