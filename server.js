import express from 'express';
import jwt from "jsonwebtoken";
import User from './User.js';
import Feedback from './Feedback.js';
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
import dns from 'dns';
import cookieParser from 'cookie-parser';
// New AWS SDK v3 imports
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import fileUpload from 'express-fileupload';
import sharp from 'sharp';
import ffmpeg from 'fluent-ffmpeg';
import validator from 'validator';
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url';
import { dirname } from 'path';


const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);



// AWS Config
const s3Client = new S3Client({
    region: process.env.AWS_REGION,
    credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
    },
});



// Utils functions

function generateOTP() {
  return Math.floor(Math.random() * (9999999 - 1000000 + 1)) + 1000000;
}

function capitalize(wd) {
  return wd.charAt(0).toUpperCase() + wd.slice(1);
}

function gcd(a, b) {
  return b ? gcd(b, a % b) : a;
}

function getCurrentUTCDate() {

  const now = new Date();

  const utcFullYear = now.getUTCFullYear();
  const utcMonth = String(now.getUTCMonth() + 1).padStart(2, '0'); 
  const utcDate = String(now.getUTCDate()).padStart(2, '0');
  const utcHours = String(now.getUTCHours()).padStart(2, '0');
  const utcMinutes = String(now.getUTCMinutes()).padStart(2, '0');
  const utcSeconds = String(now.getUTCSeconds()).padStart(2, '0');

  const fullUTCDate = `${utcFullYear}-${utcMonth}-${utcDate} ${utcHours}:${utcMinutes}:${utcSeconds} UTC`;

  return fullUTCDate

}

function findBestMatch(objects, tags) {

  let maxMatchCount = 0;
  let bestMatchId = null;

  for (let obj of objects) {
      let matchCount = 0;
      for (let tag of obj.tags) {
          if (tags.includes(tag)) {
              matchCount++;
          }
      }
      if (matchCount > maxMatchCount) {
          maxMatchCount = matchCount;
          bestMatchId = obj.id;
      }
  }

  return bestMatchId;
}


const PORT = 4050


const saltRounds = 10

dotenv.config();
const app = express()

// for cors purpose
app.use(cors({
  origin: 'http://localhost:4000', // your frontend domain
  credentials: true
}));

// Stripe Config
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

const jsonParser = bodyParser.json({
  verify: (req, res, buf) => {
    req.rawRaw = buf;
  }
});

const urlencodedParser = bodyParser.urlencoded({
  extended: true,
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
});

app.use((req, res, next) => {

  if (req.path === '/server-api/handle-post-submit/pinterest') {
    return next();
  }

  jsonParser(req, res, (err) => {
    if (err) return next(err);
    urlencodedParser(req, res, next);
  });

});


// connecting the DB
connectDB()

// helmet for security
app.use(helmet())

// validator
const verifyTokenMiddleware = async (req, res, next) => {

  cookieParser()(req, res, () => {

    const { token } = req.cookies;

    if (!token) {
      return res.status(500).send({ error: true });
    }

    jwt.verify(token, process.env.USER_JWT_SECRET, (err, decoded) => {
      if (err) {
        return res.status(500).send({ error: true });
      }

      if (decoded.type !== 'sessionToken') {
        return res.status(500).send({ error: true });
      }

      req.userId = decoded.userId; // Store user ID for use in the request handlers
      next();
    });
  });

}

// @route   POST api/create-checkout-session
// @desc    Register a new checkout session
// @access  Public

app.post('/server-api/create-checkout-session', async (req, res) => {

  const { userId, tk, paymentPlan } = req.body;

  let plan;

  if (!paymentPlan) {
    const sanitizedUserId = mongoSanitize.sanitize(userId);
    let user = await User.findOne({ _id: sanitizedUserId })
    plan = user.initialPlanChosen;
  }

  // to change the price in live mode to: price: prices.data[0].id,

  try {

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      payment_method_types: ['card', 'paypal'],
      line_items: [
        {
          price: paymentPlan || plan,
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

app.post('/server-api/webhook', async (request, response) => {

  const signature = request.headers['stripe-signature'];

  let event;

  try {
    event = stripe.webhooks.constructEvent(
      request.rawRaw.toString(),
      signature,
      endpointSecret
    );
  } catch (err) {
    console.log(`⚠️ Webhook signature verification failed.`, err.message);
    return response.sendStatus(400);
  }

  if (event.type === 'checkout.session.completed') {

    const session = event.data.object;
    const customerId = session.customer; 
    const userIdFromMetadata = session.metadata.userId;

    /// update the user onboarding ste ///
    let user = await User.findOne({ _id: userIdFromMetadata })
    if (!user) return response.status(400);
    user.onboardingStep = 2;
    user.accountStatus = 'active';
    user.socialMediaLinks.forEach(link => {
      if (link.profileStatus === 'pendingPay') {
        link.profileStatus = 'pendingAuth';
      }
    })
    user.stripeId = customerId;
    await user.save();

    return response.json({ received: true });

  }

});




app.post('/server-api/complete-account',  
[
  check('formValues.name', 'Name is required').not().isEmpty().trim().escape(),
  check('formValues.name', 'Name should be between 2 and 30 characters').isLength({ min: 2, max: 30 }),
  check('formValues.name', 'Name should only contain alphanumeric characters').isAlphanumeric(),
  check('formValues.email', 'Please include a valid email').isEmail().normalizeEmail().trim(),
  check('formValues.email').custom(value => {
    const domain = value.split('@')[1]; // Extract domain from email
    return new Promise((resolve, reject) => {
      dns.resolveMx(domain, (err, addresses) => {
        if (err) reject(new Error('Please include a valid email'));
        if (addresses && addresses.length > 0) resolve(true);
        else reject(new Error('Please include a valid email'));
      });
    });
  }),
  check('formValues.password')
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

      const { userId, formValues } = req.body

      const sanitizedUserId = mongoSanitize.sanitize(userId)

      let user = await User.findOne({ _id: sanitizedUserId  })
      if (!user || user.onboardingStep !== 0) {
        res.status(500).json({ errors: 'Server error' })
        return
      }


      user.name = formValues.name;
      user.email = formValues.email;
      /// before saving the user to the DB, encrypt the password with bcrypt ///
      user.password = await bcrypt.hash(formValues.password, await bcrypt.genSalt(saltRounds))
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


app.post('/server-api/set-up-password',  
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

app.get('/server-api/verify-checkout', async (req, res) => {

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


// @route   POST /server-api/create-portal-session
// @desc    Allow your users manage their billing info
// @access  Public

app.post('/server-api/create-customer-portal-session', async (req, res) => {

  // let user = await User.findOne({  })
  // you can use the userId to get thier cusomterId
  const { stripeCustomer } = req.body;

  // This is the url to which the customer will be redirected when they are done
  // managing their billing with the portal.
  const returnUrl = 'http://localhost:3000/settings/billing';

  const portalSession = await stripe.billingPortal.sessions.create({
    customer: stripeCustomer,
    return_url: returnUrl,
  });

  res.status(201).json({ url: portalSession.url });
  return

});



// @route   POST api/new-application
// @desc    Create a new application
// @access  Public

app.post('/server-api/new-application',
  [
    check('name', 'Name is required').not().isEmpty().trim().escape(),
    check('name', 'Name should be between 2 and 30 characters').isLength({ min: 2, max: 30 }),
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
      const allowedProfileStatus = ["inReview", "pendingPay", "pendingAuth", "active", "canceled"]
      if (!allowedProfileStatus.includes(status)) {
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
  
        // Create a new user based on the User model
        user = new User({
          name,
          email,
          applicationDate: applicationDate,
          socialMediaLinks: profileLinks,
          initialPlanChosen: initialPlanChosen,
          // add the account status
          accountStatus: 'inReview'
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

app.post("/server-api/initiate-password-change",  
[
  check("email", "Please include a valid email").isEmail().normalizeEmail()
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
    res.status(401).json({ errors: 'Invalid Email' })
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

    async function sendEmail(user, OTP) {
      const params = {
          Destination: {
              ToAddresses: [user.email]
          },
          Template: 'Password_OTP_Template',
          TemplateData: JSON.stringify({
            name: capitalize(user.name),
            OTP: OTP
          }),
          Source: 'no-reply@sumbroo.com'
      };
  
      const command = new SendTemplatedEmailCommand(params);
  
      try {
          const data = await sesClient.send(command);
          return {
            status: 200,
            response: { success: true, messageId: data.MessageId }
          };
      } catch (err) {
          console.error(err);
          return {
            status: 500,
            response: { error: 'Failed to send the email.' }
          };
      }
    }
  
    // Send the email
    const OTP = generateOTP()
    sendEmail(user, OTP).then(async result => {
      if (result.status === 200) {
        console.log("Email sent successfully:", result.response);
        // create the token here
        const payload = {
          otp: OTP,
          userId: user.id
        };
        const token = jwt.sign(payload, process.env.OTP_SECRET, { expiresIn: '15m' });
        // save the token in OnlyHttp 
        res.cookie('otpTOKEN', token, {
          httpOnly: true,
          maxAge: 15 * 60 * 1000, // 15 minutes in milliseconds
          // secure: true, // Uncomment this line if you're using HTTPS
        });
        return res.status(200).json({ ok: 'success' });
      } else {
        console.error("Error sending email:", result.response);
        return res.status(500).json({ error: "Server" });
      }
    }); 

  } catch (error) {
    console.error('Error sending email:', error);
    res.status(500).send("Server Error")
    return
  }

})


app.post("/server-api/check-password-otp",  
[
  check("otp", "Please include a valid 7-digit number.")
    .isInt({ min: 1000000, max: 9999999 })
    .isLength({ min: 7, max: 7 })
    .toInt()
], cookieParser(), 
  async (req, res) => {
    const errors = validationResult(req)
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() })
      return
    }

    const { otp } = req.body;

    const { otpTOKEN } = req.cookies;

    console.log('The otpTOKEN', otpTOKEN)

    if (!otpTOKEN) {
      return res.status(500).send('Server error');
    }

    console.log('After checking if the OTP exists.')

    jwt.verify(otpTOKEN, process.env.OTP_SECRET, (err, decoded) => {

      if (err) {
        console.log('the OTP is wrong')
        // If the token is not valid or expired, wipe out the cookie
        res.clearCookie('token');
        return res.status(401).send('Expired OTP');
      }

      console.log('this is the decoded OTP', decoded.otp)
      if (decoded.otp === otp) {
        return res.status(201).send({ success: true });
      }
      
      return res.status(400).send('Invalid OTP');

    });

})


app.post('/server-api/change-password',  
[
  check('pass')
    .isLength({ min: 8 }).withMessage('Password must be at least 8 characters long')
    .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter')
    .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
    .matches(/[0-9]/).withMessage('Password must contain at least one number')
    .matches(/[!@#$%^&*]/).withMessage('Password must contain at least one special character (!@#$%^&*)')
    .trim().escape()
], cookieParser(), async (req, res) => {
    const errors = validationResult(req)
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() })
    }

    try {

      const { otpTOKEN } = req.cookies;
      const { pass } = req.body;

      console.log(otpTOKEN, pass)

      if (!otpTOKEN) {
        return res.status(500).send('Server error');
      }
  
      jwt.verify(otpTOKEN, process.env.OTP_SECRET, async (err, decoded) => {
  
        if (err) {
          // If the token is not valid or expired, wipe out the cookie
          res.clearCookie('token');
          return res.status(401).send('Expired OTP');
        }
  
        let user = await User.findOne({ _id: decoded.userId })

        if (!user) {
          return res.status(500).send('Server error');
        }

        /// before saving the user to the DB, encrypt the password with bcrypt ///
        user.password = await bcrypt.hash(pass, await bcrypt.genSalt(saltRounds))
        /// now save the user  ///
        await user.save()
        
        return res.status(201).send({ success: true });
  
      });
      

    } catch (err) {
      console.error(err.message); // Log the error for debugging purposes.
      res.status(500).send('Server error');
      return
    }

})



// @route   POST /server-api/auth
// @desc    authenticate user
// @access  Public

app.post(
  '/server-api/auth',
  [
    check("email", "Please include a valid email").isEmail().normalizeEmail(),
    check("password", "Password is required").not().isEmpty().trim().escape()
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
          userId: user.id, 
          type: 'sessionToken'
        }

        try {
          const token = jwt.sign(payload, process.env.USER_JWT_SECRET, { expiresIn: '3h' });
          
          // Set the token as an HttpOnly cookie
          res.cookie('token', token, {
            httpOnly: true,
            // secure: true, // Uncomment this if you're using HTTPS
            maxAge: 3 * 60 * 60 * 1000 // Cookie expiration in milliseconds
          });

          res.status(201).json({ userData: {
            name: user.name,
            email: user.email
          } });
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


// @route   POST /server-api/checkToken
// @desc    Check if the user's token still valid
// @access  Public

app.post('/server-api/check-token', async (req, res) => {
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



// @route   POST /server-api/sign-out-user
// @desc    Sign out user
// @access  Private

app.post('/server-api/sign-out-user', async (req, res) => {
  try {
    res.cookie('token', '', {
      httpOnly: true,
      // secure: true, // Uncomment this if you're using HTTPS
      maxAge: 0 // This will immediately expire the cookie
    });

    return res.status(200).send({ success: true });

  } catch (err) {
    console.error('Error signing out:', err);
    return res.status(500).send({ error: true });
  }
});


// @route   POST /server-api/update-name
// @desc    Update userName
// @access  Private

app.post('/server-api/update-name', verifyTokenMiddleware,
[
  check("name")
    .isLength({ min: 6 }).withMessage('Name must be at least 6 characters long.')
    .trim()
    .escape()
], async (req, res) => {

  const errors = validationResult(req)
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() })
  } 

  try {

    const { name } = req.body;

    const userId = req.userId;

    // now update the user's name
    let user = await User.findOne({ _id: userId });

    user.name = name;
    await user.save();

    return res.status(200).send({ name: name });

  } catch (err) {
    return res.status(500).send({ error: true });
  }
});


// @route   POST /server-api/update-email
// @desc    Update user email
// @access  Private

app.post('/server-api/update-email', verifyTokenMiddleware,
  [
    check("email", "Please include a valid email").isEmail().normalizeEmail(),
  ], async (req, res) => {

  const errors = validationResult(req)
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() })
  } 

  try {

    const { email } = req.body

    const userId = req.userId

    // now update the user's email
    let user = await User.findOne({ _id: userId });

    user.email = email;
    await user.save();

    return res.status(200).send({ email: email });

  } catch (err) {
    return res.status(500).send({ error: true });
  }
});


// @route   POST /server-api/update-password
// @desc    Update user password
// @access  Private

app.post('/server-api/update-password', verifyTokenMiddleware,
  [
    check('newPass')
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

    const { newPass } = req.body;

    const userId = req.userId;

    // now update the user's password
    let user = await User.findOne({ _id: userId });

    /// before saving the user to the DB, encrypt the password with bcrypt ///
    user.password = await bcrypt.hash(newPass, await bcrypt.genSalt(saltRounds));
    await user.save();

    return res.status(200).send({ success: true });

  } catch (err) {
    return res.status(500).send({ error: true });
  }
});


// @route   POST /server-api/feedback-handler
// @desc    send Feedback to MongoDB
// @access  Private

app.post('/server-api/feedback-handler', [
  body('rating').isInt({ min: 1, max: 5 }).toInt(),
  body('feedback').trim().escape().isLength({ max: 800 })
], async (req, res) => {
  // Check for validation errors
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
  }

  try {
      const { rating, feedback } = req.body;
      const newFeedback = new Feedback({ rating, feedback });
      await newFeedback.save();

      res.status(200).json({ message: 'Feedback successfully stored!' });
  } catch (error) {
      res.status(500).json({ message: 'Server error', error });
  }
});



// @route   POST /server-api/handle-post-submit/pinterest
// @desc    handle post submit for Pinterest, then reject errors 
//          or add the data to the DB and S3
// @access  Private

app.post('/server-api/handle-post-submit/pinterest', verifyTokenMiddleware, fileUpload(), (req, res, next) => {
  try {
    console.log('Just hit the route')
    req.body.tags = JSON.parse(req.body.tags);
  } catch (e) {
    console.error('Error parsing tags field:', e);
  }
  next();
},
[
  // Validate postTitle
  body('postTitle').notEmpty().withMessage('Post title is required.').trim().escape(),

  // Validate pinTitle
  body('pinTitle')
      .notEmpty().withMessage('Pin title is required.')
      .isLength({ min: 40 }).withMessage('Pin title should be at least 40 characters.').trim().escape(),

  // Validate text
  body('text')
      .notEmpty().withMessage('Text is required.')
      .isLength({ min: 100 }).withMessage('Description should be at least 100 characters.').trim().escape(),

  // Validate pinLink
  body('pinLink')
      .notEmpty().withMessage('Pin link is required.')
      .custom((value) => {
          if (!validator.isURL(value, { require_protocol: false })) {
            throw new Error('Please provide a valid link');
          }
          return true;
      }).trim().escape(),

  // Now validate the properties of the parsed object
  body('niche').isString().notEmpty().trim().escape(),
  body('tags').isArray({ min: 4 }).withMessage('At least 4 tags should be selected.'),
  body('tags.*').isString().trim().escape(),

  // Validate image
  body('image').custom(async (value, { req }) => {

    console.log('validate the image')

    if (req.files && req.files.video) {
      return true;
    }
  
    if (!req.files || !req.files.image) {
      throw new Error('Image is required.');
    }  
  
    const image = req.files.image;
    const errors = [];
  
    try {

      const metadata = await sharp(image.data).metadata();
      const aspectRatio = metadata.width / metadata.height;
      const divisor = gcd(metadata.width, metadata.height);
      const simplifiedWidth = metadata.width / divisor;
      const simplifiedHeight = metadata.height / divisor;
  
      if (image.size > 20 * 1048576) {
        errors.push(`Image size must not exceed 20MB. This image's size is ${(image.size / 1048576).toFixed(2)}MB.`);
      }
      if (!['jpeg', 'png', 'tiff', 'webp', 'bmp'].includes(metadata.format)) {
        errors.push(`Image type must be of a BMP/JPEG/PNG/TIFF/WEBP format. This is a ${metadata.format.toUpperCase()} image.`);
      }
      if (Math.abs(2/3 - aspectRatio) > 0.2 && Math.abs(9/16 - aspectRatio) > 0.2) {
        errors.push(`Image aspect ratio must be 2:3 or 9:16. This image is ${simplifiedWidth}:${simplifiedHeight}.`);
      }
      if (metadata.width < 1000 || metadata.height < 1500) {
        errors.push(`Image resolution must be at least 1000px by 1500px. This image is ${metadata.width}px by ${metadata.height}px.`);
      }
    } catch (error) {
      errors.push('Invalid image file.');
    }
  
    if (errors.length) {
      throw new Error(errors);
    }

    return true;

  }),
  
  // Validate video
  body('video').custom(async (value, { req }) => {

    if (req.files && req.files.image) {
      return true;
    }
  
    if (!req.files || !req.files.video) {
      throw new Error('Video is required.');
    }
  
    const video = req.files.video;
    const errors = [];
  
    // Check file size (in bytes)
    if (video.size > 2e9) {
      errors.push(`Video size must be less than 2GB. This video's size is ${(video.size / 1e9).toFixed(2)}GB.`);
    }

    const tempFilePath = path.join(__dirname, 'tempfile' + Date.now());
  
    return new Promise((resolve, reject) => {

      fs.writeFile(tempFilePath, video.data, (err) => {

        if (err) {
          errors.push('Failed to write temporary file.');
          return reject(new Error(errors.join(' ')));
        }

        ffmpeg.ffprobe(tempFilePath, (err, metadata) => {

          if (err) {
            console.log(err)
            errors.push('Invalid video file.');
            fs.unlink(tempFilePath, (err) => {
              if (err) {
                console.error('Failed to delete temporary file:', err);
              }
            });
            return reject(new Error(errors.join(' ')));
          }
    
          const videoStream = metadata.streams.find(stream => stream.codec_type === 'video');
          if (!videoStream) {
            errors.push('No valid video stream found.');
            fs.unlink(tempFilePath, (err) => {
              if (err) {
                console.error('Failed to delete temporary file:', err);
              }
            });
            return reject(new Error(errors.join(' ')));
          }
    
          const aspectRatio = videoStream.width / videoStream.height;
          const divisor = gcd(videoStream.width, videoStream.height);
          const simplifiedWidth = videoStream.width / divisor;
          const simplifiedHeight = videoStream.height / divisor;
    
          if (Math.abs(2/3 - aspectRatio) > 0.2 && Math.abs(9/16 - aspectRatio) > 0.2) {
            errors.push(`Video aspect ratio must be 9:16 or 2:3. This video has ${simplifiedWidth}:${simplifiedHeight} ratio.`);
          }
    
          if (videoStream.width < 540 || videoStream.height < 960) {
            errors.push(`Video resolution must be at least 540px by 960px. This video is ${videoStream.width}px by ${videoStream.height}px.`);
          }
    
          const duration = metadata.format.duration;
          if (duration > 300 || duration < 4) {
            errors.push(`Video duration must be at least 4 seconds and at most 5 minutes. This video is ${duration.toFixed(2)} seconds long.`);
          }

          fs.unlink(tempFilePath, (err) => {
            if (err) {
              console.error('Failed to delete temporary file:', err);
            }
          });
    
          if (errors.length) {
            return reject(new Error(errors));
          }
    
          resolve(true);
  
        });

      })

    });
  }),

], async (req, res) => {

  const errors = validationResult(req)
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() })
  } 

  try {

    // destructure the data
    const { postTitle, pinTitle, text, pinLink, niche, tags } = req.body;

    // Destructure validated media files from req.files
    const { image, video } = req.files;

    const userId = req.userId;

    // before you register the new post
    // check if the user has already posted in the last 24H
    // by sorting getting the date of the latest post and 
    // comparing it with the current day and hour
    // otherwise return error 505
    
    // here you have to save the data to the DB
    // effectivley creating a new post by platform

    const pipeline = [
      {
        $match: {
          _id: userId, 
        },
      },
      { $unwind: '$socialMediaLinks' },
      { $unwind: '$socialMediaLinks.posts' },
      {
        $group: {
          _id: null,
          maxPublishingDate: { $max: '$socialMediaLinks.posts.lastPublished' },
        },
      },
    ];

    let result;
    try {
      result = await User.aggregate(pipeline);
    } catch (error) {
      console.error(error);
    } 

    const maxDate = result[0]?.maxPublishingDate;

    // checking if the user has already pusblished a post in the last 24H
    // here the date is in UTC
    // This is just a check up cuz I already implemented the check in the front-end
    // If users try to game the system they will get an error telling them to fuck off.
    if (maxDate && maxDate >= getCurrentUTCDate()) {

      return res.status(500).send({ error: err });
      
    } else {

      let user = await User.findOne({ _id: userId })   

      const FILE_KEY = 'pinterest-' + userId;

      // Upload the file to S3
      const command = new PutObjectCommand({
        Bucket: 'sumbroo-media-upload',
        Key: FILE_KEY,
        Body: image ? image.data : video.data, // This should be the file stream or file buffer
        ACL: "public-read",  // To allow the file to be publicly accessible
        ContentType: image ? image.mimetype : video.mimetype
      });
  
      await s3Client.send(command);
  
      // Construct the file URL
      const fileUrl = `https://sumbroo-media-upload.s3.us-east-1.amazonaws.com/${FILE_KEY}`;

      // here you have to pick the target user, aka the host, then save his/her userId
      // in the database.

      const tagsResult = await User.aggregate([

        // Unwind the socialMediaLinks array to denormalize the data
        { $unwind: "$socialMediaLinks" },
      
        // Match users that have the provided niche and don't have the provided ID
        {     
          $match: { 
            "socialMediaLinks.niche": niche, 
            _id: { $ne: userId }, 
            accountStatus: "active", 
            "socialMediaLinks.profileStatus": "active", 
            "socialMediaLinks.platformName": "pinterest"   // HERE SHOULD BE CONVERTED TO DYNAMIC VARIABLE 'platform'
          }  
        },
      
        // Group by user ID to aggregate the unique tags for each user
        {
          $group: {
            _id: "$_id", // User's ID
            tags: { $addToSet: "$socialMediaLinks.audience" }
          }
        },
      
        // Flatten the tags array and project the final structure with the user's ID
        {
          $project: {
            _id: 0, 
            id: "$_id",
            tags: {
              $reduce: {
                input: "$tags",
                initialValue: [],
                in: { $setUnion: ["$$value", "$$this"] }
              }
            }
          }
        }
      ]);

      const hostId = findBestMatch(tagsResult, tags)

      // Create a new post
  
      const newPost = {
        postTitle: postTitle, 
        hostUserId: hostId,
        postStatus: "in review", // Set the initial status to "in review"
        platform: "pinterest", // Set the platform to "pinterest"
        content: {
            media: {
                mediaType: image ? "image" : "video", // Determine the media type based on the presence of image or video
                awsLink: fileUrl, // Set the AWS link to the file URL you constructed
            },
            textualData: {
                pinterest: {
                    title: pinTitle, // Set the Pinterest title to the pinTitle from the request body
                    description: text, // Set the description to the text from the request body
                    destinationLink: pinLink, // Set the destination link to the pinLink from the request body
                },
            },
        },
        publishingDate: getCurrentUTCDate(), // this is to keep track
        targetingNiche: niche, // Set the targeting niche to the niche from the request body
        targetingTags: tags, // Set the targeting tags to the tags from the request body
      };
  
      // Find the correct social media link
      let socialMediaLink = user.socialMediaLinks.find(link => link.platformName === "pinterest");

      // Add the new post to the posts array of the correct social media link
      socialMediaLink.posts.push(newPost);

      // Save the user document
      await user.save();
  
      return res.status(200).send({ success: true }); 

    }

  } catch (err) {
    console.log(err)
    return res.status(500).send({ error: err });
  }

});


app.listen(PORT, () => {
  console.log(`App listening on port ${PORT}`)
})