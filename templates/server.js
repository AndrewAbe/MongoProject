const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');

const app = express();

// Replace with your MongoDB Atlas connection string
const mongoUri = 'mongodb://localhost:27017';
mongoose.connect(mongoUri, { useNewUrlParser: true, useUnifiedTopology: true });

const userSchema = new mongoose.Schema({
  firstName: String,
  lastName: String,
  username: String,
  phoneNumber: String,
  email: String,
  address: String,
  dob: Date,
  password: String, // Remember to hash passwords before saving
});

const User = mongoose.model('User', userSchema);

// Body-parser middleware to parse form data
app.use(bodyParser.urlencoded({ extended: true }));

app.post('/register', (req, res) => {
  const newUser = new User({
    firstName: req.body.first_name,
    lastName: req.body.last_name,
    username: req.body.username,
    phoneNumber: req.body.phone_number,
    email: req.body.email,
    address: req.body.address,
    dob: req.body.dob,
    password: req.body.password, // Make sure to hash the password before storing
  });

  newUser.save()
    .then(() => res.status(200).send('Registration successful!'))
    .catch(err => res.status(500).send('Error registering new user.'));
});

app.get('/friends', (req, res) => {
  User.find({}, 'firstName -_id', (err, users) => {
    if (err) {
      res.status(500).send('Error fetching users.');
    } else {
      res.json(users);
    }
  });
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on port ${port}`));
