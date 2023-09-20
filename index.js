require("dotenv").config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const {User, Admin, Course} = require('./models/index');

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cors());
const secret = process.env.SECRET_KEY;
const url = process.env.DB_URL;

// const connect = async () => {
//      await mongoose.connect(url);
// }
mongoose.connect(url)
.catch(e => console.log("mongoose error " +  e));


const generateToken = (username, userId) => {
    const token = jwt.sign({username, userId}, secret, {expiresIn: '24h'});
    return token;
}

const authenticateAdmin = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if(authHeader){
       const token = authHeader.split(' ')[1];  
        if(token){
            jwt.verify(token, secret, (err, user) => {
                if(err) {
                    res.status(403).json({message: "You are not authorized"});
                } else {
                    req.user = user;
                    next();
                }
            })
        } else {
            res.sendStatus(403);
        }
    } else {
        res.sendStatus(403);
    }
   
}


app.get('/', authenticateAdmin, (req, res) => {
    console.log(req.user);
    res.json({user: req.user});
})

app.post('/admin/signup', async (req, res) => {
    const {firstname, lastname, username, password} = req.body;
    const foundAdmin = await Admin.findOne({username});
    const hashedPassword = await bcrypt.hash(password, 10);

    if(foundAdmin){
        res.status(401).json({message: "This user already exist."});
    } else {
        console.log(hashedPassword);
        const newAdmin = new Admin({
            firstname: firstname,
            lastname: lastname,
            username: username, 
            password: hashedPassword, 
        });
        await newAdmin.save();
        const token = generateToken(username, newAdmin._id);
        res.status(200).json({message: "Sign up was successful", token, newAdmin});
    }
})

app.post('/admin/login', async (req, res) => {
    const {username, password} = req.body;
    const foundAdmin = await Admin.findOne({username});
    // console.log(foundAdmin);

    if(foundAdmin && (await bcrypt.compare(password, foundAdmin.password))){
        const token = generateToken(username, foundAdmin._id);
        res.status(200).json({message: "You are logged in", token, foundAdmin});
    } else {
        res.status(401).json({message: "Username/password doesn't match"});
    }    
})

app.post('/admin/addcourse', authenticateAdmin, async (req, res) => {
    const {title, description, price, image, published, createdBy} = req.body;
    try{
        const newCourse = new Course({
            title: title,
            description: description,
            price: price,
            imageLink: image,
            published: published,
            createdBy: createdBy
        });
        await newCourse.save();
        res.status(200).json({message: "Course was successfully created", newCourse});
    } catch(err){
        res.status(400).json({message: "Unable to create course"});
    }   
})



app.get('/admin/courses', authenticateAdmin, async (req, res) => {
    const courses = await Course.find({});
    res.json({courses});
})

app.get('/admin/courses/:userId', authenticateAdmin, async (req, res) => {
    const {userId} = req.params;
    const courses = await Course.find({ createdBy: {$eq: userId} });
    res.json({courses});
})

app.put('/admin/courses/:courseId', authenticateAdmin, async (req, res) => {
    const {courseId} = req.params;
    // console.log('course id ' + courseId);
    const updates = req.body;
    const foundCourse = await Course.findByIdAndUpdate(courseId, updates, {new: true});

    if(foundCourse){
        // foundCourse.title = updates.title;
        // foundCourse.description = updates.description;
        // foundCourse.price = updates.price;
        // foundCourse.imageLink = updates.imageLink;
        // foundCourse.published = updates.published
        res.status(200).json({message: "course updated successfully", foundCourse})
    } else {
        res.status(404).json({message: "unable to find the course"});
    }
    
})


app.post('/admin/logout', async (req, res) => {
    res.status(200).json({messsage: "user logged out"});
})


app.listen('3004', ()=> {
    console.log("listening to port 3004");
   })



