const express = require('express');
const router = express.Router();
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const { check, validationResult } = require('express-validator/check');
//import mongoose User schema from model
const User = require('../../models/User');

// @route    POST api/users
// @desc     Register user
// @access   Public
router.post(
  '/',
  [
    check('name', 'Name is required')
      .not()
      .isEmpty(),
    check('email', 'Please include a valid email').isEmail(),
    check(
      'password',
      'Please enter a password with 6 or more characters'
    ).isLength({ min: 6 })
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, password } = req.body;

    try {
      //check if user already exist
      let user = await User.findOne({ email });

      if (user) {
        return res
          .status(400)
          .json({ errors: [{ msg: 'User already exists' }] });
      }
//email,{options-size, reading (ni nakedd people),d for default avatar)}
      const avatar = gravatar.url(email, {
        s: '200',
        r: 'pg',
        d: 'mm'
      });
      //create instance then enc save seprately using user.save()
      user = new User({
        name,
        email,
        avatar,
        password
      });
      //promise hence await(10 rounds for secure ) salt is length to generate password 
      const salt = await bcrypt.genSalt(10);
      //put hashed password in user instance
      user.password = await bcrypt.hash(password, salt);
      //save user
      //it returns promise so put await
      await user.save();
      //payload is object with user 
      const payload = {
        user: {
          //no _id
          id: user.id
        }
      };
      //put payload and secret key in jwt auth 
      jwt.sign(
        payload,
        config.get('jwtSecret'),
        { expiresIn: 360000 },
        (err, token) => {
          if (err) throw err;
          //if no error then send token to client
          res.json({ token });
        }
      );
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server error');
    }
  }
);

module.exports = router;
