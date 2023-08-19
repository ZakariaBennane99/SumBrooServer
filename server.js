import express from 'express';
import jwt from "jsonwebtoken";
import User from './User.js';
import helmet from 'helmet';
import { check, validationResult, body } from 'express-validator';
import dotenv from 'dotenv';
import cors from 'cors';
import bodyParser from 'body-parser';
import connectDB from './db.js';
import bcrypt from 'bcrypt'
import Stripe from 'stripe';
import mongoSanitize from 'express-mongo-sanitize';
import { SESClient, SendTemplatedEmailCommand } from "@aws-sdk/client-ses";
import dns from 'dns'


const PORT = 4050


const saltRounds = 10

dotenv.config();
const app = express()

// for cors purpose
app.use(cors())

// Stripe Config
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

app.use(bodyParser.json({
  verify: (req, res, buf) => {
    console.log("Inside verify function");
    req.rawBody = buf;
  }
}));

app.use(bodyParser.urlencoded({
  extended: true,
  verify: (req, res, buf) => {
    console.log("Inside verify function");
    req.rawBody = buf;
  }
}));



// connecting the DB
connectDB()

// helmet for security
app.use(helmet())

// @route   POST api/create-checkout-session
// @desc    Register a new checkout session
// @access  Public

app.post('/api/create-checkout-session', async (req, res) => {

  const { userId, tk } = req.body

  const sanitizedUserId = mongoSanitize.sanitize(userId);

  let user = await User.findOne({ _id: sanitizedUserId })

  const paymentPlan = user.initialPlanChosen

  // to change the price in live mode to: price: prices.data[0].id,

  try {

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      payment_method_types: ['card', 'paypal'],
      line_items: [
        {
          price: paymentPlan,
          quantity: 1
        },
      ],
      success_url: `http://localhost:3000/settings/linked-accounts?grub=${tk}`,
      // take him back to the onboarding page
      cancel_url: 'http://localhost:3000/sign-in',
      metadata: {
        userId: userId.toString()
      }
    });

    res.json({ url: session.url });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }

});


// @route   POST /webhook
// @desc    listen for the 'checkout.session.completed' event
// @access  Public

const endpointSecret = "whsec_7db5efb5afb9156ffd05dbf44beebea183b0c956aa689170771b5cd8f20c872d";

app.post('/api/webhook', async (request, response) => {

  console.log('Its running')

  const signature = request.headers['stripe-signature'];

  console.log("Stripe Signature:", signature);

  let event;

  console.log(request.rawBody);

  try {
    event = stripe.webhooks.constructEvent(
      request.rawBody,
      signature,
      endpointSecret
    );
  } catch (err) {
    console.log(`⚠️  Webhook signature verification failed.`, err.message);
    return response.sendStatus(400);
  }

  console.log('Just Before the event')
  if (event.type === 'checkout.session.completed') {

    const session = event.data.object;
    const customerId = session.customer; 
    const userIdFromMetadata = session.metadata.userId;

    /// update the user onboarding ste ///
    let user = await User.findOne({ _id: userIdFromMetadata })
    if (!user) return response.status(400);
    user.onboardingStep = 2
    user.stripeId = customerId
    await user.save()

    return response.json({ received: true });

  }

});

app.post('/api/set-up-password',  
[
  check('pass')
    .isLength({ min: 8 }).withMessage('Password must be at least 8 characters long')
    .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter')
    .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
    .matches(/[0-9]/).withMessage('Password must contain at least one number')
    .matches(/[!@#$%^&*]/).withMessage('Password must contain at least one special character (!@#$%^&*)')
    .trim().escape()
], async (req, res) => {
    const errors = validationResult(req)
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() })
    }

    try {

      const { userId, pass } = req.body

      const sanitizedUserId = mongoSanitize.sanitize(userId)

      let user = await User.findOne({ _id: sanitizedUserId  })
      if (!user || user.onboardingStep !== 0) {
        res.status(500).json({ errors: 'Server error' })
        return
      }
    
      /// before saving the user to the DB, encrypt the password with bcrypt ///
      user.password = await bcrypt.hash(pass, await bcrypt.genSalt(saltRounds))
      // update the user onboarding step
      user.onboardingStep = 1
      /// now save the user and the profile to the DB ///
      await user.save()

      // now create a token for the payment
      const payload = {
        userId: userId,
        action: 'payment'
      }
    
      jwt.sign(payload,
        process.env.JWT_SECRET,
        { expiresIn: '1h' },
        (err, token) => {
            if (err) throw err;
    
            res.status(201).json({ success: true, token: token });
            return;
        });

    } catch (err) {
      console.error(err.message); // Log the error for debugging purposes.
      res.status(500).send('Server error');
      return
    }

})

app.get('/api/verify-checkout', async (req, res) => {

  const { session_id } = req.query

  try {

    const session = await stripe.checkout.sessions.retrieve(session_id)

    let user = await User.findOne({ email })

    const payload = {
      user: {
          // the id is automatically generated by MongoDB
          id: user.id
      }
    }

    // the following will return a token generated for the user
    jwt.sign(payload,
      process.env.USER_JWT_SECRET,
      { expiresIn: 2592000 },
      (err, token) => {
          if (err) throw err
          const s = {
              token: token,
              userData: {
                  name: user.name,
                  email: user.email,
                  dbId: user.id,
                  stripeId: user.customerId
              }
          }
          res.status(201).json(s)
          return
      })

  } catch (error) {
    // Handle the error
    res.status(500).json({ error: error.message })
  }
})


// @route   POST /api/create-portal-session
// @desc    Allow your users manage their billing info
// @access  Public

app.post('/api/create-customer-portal-session', async (req, res) => {

  // let user = await User.findOne({  })
  // you can use the userId to get thier cusomterId
  const { customerId } = req.body;

  console.log('inside the create portal', customerId)
  // This is the url to which the customer will be redirected when they are done
  // managing their billing with the portal.
  const returnUrl = 'http://localhost:3000/settings/billing';

  const portalSession = await stripe.billingPortal.sessions.create({
    customer: customerId,
    return_url: returnUrl,
  });

  console.log('the portalSession', portalSession)

  res.status(201).json({ url: portalSession.url });
  return

});



// @route   POST api/new-application
// @desc    Create a new application
// @access  Public

app.post('/api/new-application',
  [
    check('name', 'Name is required').not().isEmpty().trim().escape(),
    check('name', 'Name should be between 5 and 30 characters').isLength({ min: 5, max: 30 }),
    check('name', 'Name should only contain alphanumeric characters').isAlphanumeric(),
    check('email', 'Please include a valid email').isEmail().normalizeEmail().trim(),
    check('email').custom(value => {
      const domain = value.split('@')[1]; // Extract domain from email
      return new Promise((resolve, reject) => {
        dns.resolveMx(domain, (err, addresses) => {
          if (err) reject(new Error('Please include a valid email'));
          if (addresses && addresses.length > 0) resolve(true);
          else reject(new Error('Please include a valid email'));
        });
      });
    }),
    check("initialPlanChosen", "Server error").not().isEmpty().trim().escape(),
    body("profileLinks.*.platformName").custom((platform, { req }) => {
      const allowedPlatforms = ["pinterest", "tiktok", "twitter", "youtube"];
      if (!allowedPlatforms.includes(platform)) {
        throw new Error(`Server error`);
      }
      return true;
    }),
    body("profileLinks.*.profileLink").custom((link, { req }) => {
      const platform = req.body.profileLinks.find(item => item.profileLink === link).platformName;
  
      const validators = {
        pinterest: /^https:\/\/www\.pinterest\.com\/[a-zA-Z0-9_\-]+\/?$/,
        tiktok: /^https:\/\/www\.tiktok\.com\/@[a-zA-Z0-9_.\-]+\/?$/,
        twitter: /^https:\/\/twitter\.com\/[a-zA-Z0-9_]+\/?$/,
        youtube: /^https:\/\/www\.youtube\.com\/(channel\/UC[a-zA-Z0-9_-]{22}|user\/[a-zA-Z0-9_-]+)/
      };
  
      if (!validators[platform].test(link)) {
        throw new Error(`Invalid link for ${platform.charAt(0).toUpperCase() + platform.slice(1)}`);
      }
  
      return true;

    }).trim().escape(),
    body("profileLinks.*.profileStatus").custom((status, { req }) => {
      const allowedProfileStatus = ["new","disabled", "active", "pending"]
      if (!allowedProfileStatus .includes(status)) {
        throw new Error(`Server error`);
      }
      return true;
    })
  ],
  async (req, res) => {
      const errors = validationResult(req)
      if (!errors.isEmpty()) {
          return res.status(400).json({ errors: errors.array() })
      }

      try {
        const { applicationDate, name, email, profileLinks, initialPlanChosen } = req.body;
    
        let user = await User.findOne({ email });
    
        if (user) {
            return res.status(401).json({ errors: [{ msg: "User already exists" }] });
        }
    
        console.log(typeof applicationDate, applicationDate)

        // Create a new user based on the User model
        user = new User({
            name,
            email,
            applicationDate: applicationDate,
            socialMediaLinks: profileLinks,
            initialPlanChosen: initialPlanChosen,
            // add the account status
            accountStatus: 'new'
        });
    
        // Save the user to the database
        await user.save();
    
        res.status(201).send('ok');
        return

      } catch (err) {
          console.error(err.message); // Log the error for debugging purposes.
          res.status(500).send('Server error');
          return
      }

})


// @route   POST api/change-password
// @desc    send an email for password change
// @access  Public

app.post("/api/change-password",  
[
  check("email", "Please include a valid email.").isEmail().normalizeEmail()
],
  async (req, res) => {
  const errors = validationResult(req)
  if (!errors.isEmpty()) {
    res.status(400).json({ errors: errors.array() })
    return
  }

  const { email } = req.body

  let user = await User.findOne({ email })

  if (!user) {
    res.status(200).send({ success: true })
    return
  }

  // set up AWS SES
  const sesClient = new SESClient({
    region: process.env.AWS_REGION,
    credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
    }
  });

  try {

    res.status(200).send(token)
  } catch (error) {
    console.error('Error sending email:', error);
    res.status(500).send("Server Error")
  }

})


// @route   POST /api/auth
// @desc    authenticate user
// @access  Public
app.post(
  '/api/auth',
  [
    check("email", "Please include a valid email.").isEmail().normalizeEmail(),
    check("password", "Password is required.").not().isEmpty().trim().escape()
  ],
  async (req, res) => {
      const errors = validationResult(req)
      if (!errors.isEmpty()) {
        res.status(400).json({ errors: errors.array() })
        return
      }

      // destructuring the request
      const { email, password } = req.body

      try {

        let user = await User.findOne({ email })

        // if the user doesn't exists
        if (!user) {
          res.status(401).json({ errors: [{ msg: "Invalid Credentials" }] })
          return
        }

        if (user.accountStatus !== 'active') {
          res.status(401).json({ errors: [{ msg: "Invalid Credentials" }] })
          return
        }

        const isMatch = bcrypt.compareSync(password, user.password)

        if (!isMatch) {
          res.status(401).json({ errors: [{ msg: "Invalid Credentials" }] })
          return
        }

        // now create a token session of 3-4H
        const payload = {
          userId: user.id
        }

        try {
          const token = await signToken(payload, process.env.USER_JWT_SECRET, { expiresIn: '3h' });
          
          // Set the token as an HttpOnly cookie
          res.cookie('token', token, {
              httpOnly: true,
              // secure: true, // Uncomment this if you're using HTTPS
              maxAge: 3 * 60 * 60 * 1000 // Cookie expiration in milliseconds
          });
  
          const s = {
              userId: user.id
          };
          res.status(201).json(s);
          return
        } catch (err) {
          // Handle the error appropriately
          console.error(err);
          res.status(500).json({ error: 'Server Error' });
          return
        }

      } catch(err) {
        res.status(500).send("Server Error")
        return
      }
})


// @route   POST /api/checkToken
// @desc    Check if the user's token still valid
// @access  Public

app.post('/api/checkToken', async (req, res) => {
      // get the token from the header
      const token = req.header("x-auth-token")

      try {
          // check if no token
          if (!token) {
              // 401 means not authorized
              res.status(404).json({ msg: "No token" })
              return
          }

          // verify token
          try {
              const decoded = jwt.verify(token, process.env.USER_JWT_SECRET)
              // setting the user who sends the request to decoded.user
              // which is basically the user associated with the token
              res.status(200).json({ msg: "Token is verified", userID: decoded.user })
              return
          } catch(err) {
              res.status(401).json({ msg: "Your Session Has Expired, Please Sign In Again!" })
              return
          }
      } catch(err) {
          console.log(err)
          res.status(500).json({ msg: 'Server error' })
          return
      }
})



app.listen(PORT, () => {
  console.log(`App listening on port ${PORT}`)
})