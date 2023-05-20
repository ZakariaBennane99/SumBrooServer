import express from 'express';
import jwt from "jsonwebtoken";
import User from './User.js';
import { Configuration, OpenAIApi } from "openai";
import helmet from 'helmet';
import { check, validationResult, body } from 'express-validator';
import dotenv from 'dotenv';
import cors from 'cors';
import bodyParser from 'body-parser';
import { decode } from 'html-entities';
import { parse } from 'node-html-parser';
import connectDB from './db.js';
import bcrypt from 'bcrypt'
import puppeteer from 'puppeteer-extra';
import Stripe from 'stripe';
import { BingAIClient } from '@waylaidwanderer/chatgpt-api';
import sdk from 'microsoft-cognitiveservices-speech-sdk';
import Mailjet from 'node-mailjet'
//// add stealth plugin and use defaults (all evasion techniques)
import StealthPlugin from 'puppeteer-extra-plugin-stealth';
puppeteer.use(StealthPlugin());

const saltRounds = 10

dotenv.config();
const app = express()

// for cors purpose
app.use(cors())

// Stripe Config
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

// for body-parser
app.use(bodyParser.json({ limit: '150mb' }))
app.use(bodyParser.urlencoded({ limit: '150mb', extended: true }))

// connecting the DB
connectDB()

// helmet for security
app.use(helmet())

// OpenAi Config
const configuration = new Configuration({
    apiKey: process.env.OPENAI_API_KEY,
})

// bing search config
const options = {
  // Necessary for some people in different countries, e.g. China (https://cn.bing.com)
  host: '',
  // "_U" cookie from bing.com
  userToken: '1RsPPdSYkcNcHfiRUrUIq9koO1ZNvvI7ikjI5i7g9ce0Tl8wz9Px4Rhvgh-NUq7uqFwBp7NZrJtSrLclRMoAUsbq6_YZTUNQPdIdscEVDdy9d6pJ5zxq4Omic8wle6D0qId7zKlDm3C5tpHuxN92VywAr0X6djWiZ1HJInPY_yKeYueYVkFznOfBDMiL4bR8doLdSxjgnG8sjKyrsLxJ3WMAyqSgmliSbI52dag7WPtU',
  // If the above doesn't work, provide all your cookies as a string instead
  cookies: '',
  // A proxy string like "http://<ip>:<port>"
  proxy: '',
  // (Optional) Set to true to enable `console.debug()` logging
  debug: false,
};

// you should be keeping an Eye on this, and updating it every once and a while
// because only a reversed Proxy of the
const bingAIClient = new BingAIClient(options);

const openai = new OpenAIApi(configuration);


// @route   POST api/create-checkout-session
// @desc    Register a new checkout session
// @access  Public

app.post('/api/create-checkout-session', async (req, res) => {

  const prices = await stripe.prices.list({
    lookup_keys: [req.body.lookup_key],
    expand: ['data.product'],
  });

  try {
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      payment_method_types: ['card', 'paypal'],
      line_items: [
        {
          price: prices.data[0].id,
          quantity: 1
        },
      ],
      success_url: 'http://localhost:3000/home',
      cancel_url: 'http://localhost:3000/',
      subscription_data: {
        trial_period_days: 2,
      },
      custom_fields: [
        {
          key: 'email',
          label: {
            type: 'custom',
            custom: 'Email for SwiftNotion (Same as above)',
          },
          type: 'text',
        },
        {
          key: 'password',
          label: {
            type: 'custom',
            custom: 'Create New Password for SwiftNotion',
          },
          type: 'password',
        },
      ],
    });

    res.json({ url: session.url });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// @route   POST /webhook
// @desc    listen for the 'checkout.session.completed' event
// @access  Public

app.post('/webhook', bodyParser.raw({type: 'application/json'}), (request, response) => {
  const sig = request.headers['stripe-signature'];

  let event;

  try {
    event = stripe.webhooks.constructEvent(request.body, sig, endpointSecret);
  } catch (err) {
    return response.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;

    const nameField = session.custom_fields.find(field => field.key === 'name');
    const emailField = session.custom_fields.find(field => field.key === 'email');
    const passwordField = session.custom_fields.find(field => field.key === 'password');

    const name = nameField.text.value;
    const email = emailField.text.value;
    const password = passwordField.text.value;

    console.log(name, email, password)

  }

  response.json({received: true});
});





// @route   POST api/users
// @desc    Register user
// @access  Public

app.post(
  '/api/users',
  [
    check("name", "Name is required").not().isEmpty(),
    check("email", "Please include a valid email").isEmail(),
    check("password", "Password should be of 6 characters or more").isLength({ min:6 })
  ],
  async (req, res) => {
      const errors = validationResult(req)
      if (!errors.isEmpty()) {
          return res.status(400).json({ errors: errors.array() })
      }
      // destructuring the request
      const { name, email, password, verified } = req.body
      try {
          let user = await User.findOne({ email })

          if (user) {
              // 401 is not the right response, but this is just a temporary solution
              res.status(401).json({ errors: [{ msg: "User already exists" }] })
          }

          /// creating the user ///
          user = new User({
            name: name,
            email: email,
            password: password
          })

          /// before saving the user to the DB, encrypt the password with bcrypt ///
          user.password = await bcrypt.hash(password, await bcrypt.genSalt(saltRounds))

          /// now save the user and the profile to the DB ///
          await user.save()
          res.status(201).send(user.id)
      } catch(err) {
          console.error(err.message)
          res.status(500).send("Server Error")
      }
})


// @route   POST api/auth
// @desc    Authenticate user
// @access  Public

app.post(
  '/api/auth',
  [
      check("email", "Please include a valid email").isEmail(),
      check("password", "Password is required").not().isEmpty()
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

          const isMatch = await bcrypt.compareSync(password, user.password)

          if (!isMatch) {
              // for security reasons (the user doesn't exists or the password is incorrect)
              // it is good to send the same error message
              res.status(401).json({ errors: [{ msg: "Invalid Credentials" }] })
              return
          }

          // check if verified
          if (user.verified) {
              /// return jsonwebtoken to be used with protected routes ///
              const payload = {
                  user: {
                      // the id is automatically generated by MongoDB
                      id: user.id
                  }
              }

              // the following will return a token generated for the user
              jwt.sign(payload,
                  process.env.USER_JWT_SECRET,
                  // ! Do Not Forget To transform it Back To 3600s In Production
                  { expiresIn: 2592000 },
                  (err, token) => {
                      if (err) throw err
                      const s = {
                          token: token,
                          userData: {
                              name: user.name,
                              email: user.email,
                              id: user.id
                          }
                      }
                      res.status(201).json(s)
                      return
                  })
          } else {
              res.status(403).json({ errors: [{ msg: "Email Unverified" }] })
              return
          }

      } catch(err) {
          console.error(err.message)
          res.status(500).send("Server Error")
          return
      }
})


// @route   POST api/auth/checkToken
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


// @route   POST api/email-verification
// @desc    verify user's email
// @access  Public

app.post("/api/email-verification", async (req, res) => {

  // connect to MailJet
  const mailjet = new Mailjet({
    apiKey: process.env.MAILJET_API_KEY,
    apiSecret: process.env.MAILJET_API_SECRET
  })

  const { name, email, userId } = req.body

  try {
    const result = await mailjet.post('send', { version: 'v3.1' }).request({
      Messages: [
        {
          From: {
            Email: 'hey@swiftnotion.co',
            Name: 'SwiftNotion'
          },
          To: [
            {
              Email: email,
            },
          ],
          TemplateID: 4740627,
          TemplateLanguage: true,
          Subject: 'Verify Your Email',
          Variables: {
            USER_ID: userId,
            NAME: name
          }
        },
      ],
    });

    console.log('Email sent successfully:', result.body);
    res.status(201).send("Email sent")
  } catch (error) {
    console.error('Error sending email:', error);
    res.status(500).send("Server Error")
  }

})


// @route   POST api/verify-user-email
// @desc    updare the user's status to verified
// @access  Public

app.post("/api/verify-user-email", async (req, res) => {

  const { userId } = req.body

  try {
      let user = await User.findById(userId)
      if (user) {
          user.verified = true
          user.save()
          res.status(201).send("User has been verified")
      } else {
          res.status(404).send("User not found")
      }
  } catch (err) {
      console.log(err.message)
      res.status(500).send("Server Error")
  }
})


// @route   POST api/user
// @desc    Get profile by user email
// @access  Public

app.post("/api/user", [ check("email", "Please include a valid email").isEmail() ], async (req, res) => {

  const errors = validationResult(req)
  if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() })
      return
  }

  try {
      console.log(req.body.email)
      const profile = await User.findOne({ email: req.body.email })
      console.log(profile)
      if (!profile) {
          res.status(401).json({ msg: "This email is not associated with any user" })
          return
      }
      res.status(201).json(profile)
      return
  } catch (err) {
      console.log(err.message)
      res.status(500).send("Server Error")
      return
  }

})


// @route   POST api/change-password
// @desc    send an email for password change
// @access  Public

app.post("/api/change-password", async (req, res) => {

  // connect to MailJet
  const mailjet = new Mailjet({
    apiKey: process.env.MAILJET_API_KEY,
    apiSecret: process.env.MAILJET_API_SECRET
  })

  const { name, email, userId } = req.body

  try {
    const result = await mailjet.post('send', { version: 'v3.1' }).request({
      Messages: [
        {
          From: {
            Email: 'hey@swiftnotion.co',
            Name: 'SwiftNotion'
          },
          To: [
            {
              Email: email,
            },
          ],
          TemplateID: 4740696,
          TemplateLanguage: true,
          Subject: 'Password Reset',
          Variables: {
            USER_ID: userId,
            NAME: name
          }
        },
      ],
    });

    /// return jsonwebtoken ///
    const payload = {
      user: {
        id: userId
      }
    }

    //// the following will return a token generated for the link for 10 Min
    const token = jwt.sign(payload, process.env.USER_JWT_SECRET,
      { expiresIn: 600 },
      (err, token) => {
          if (err) throw err
          return res.json({ token })
    })

    console.log('Email sent successfully:', result.body);
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
      check("email", "Please include a valid email").isEmail(),
      check("password", "Password is required").not().isEmpty()
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

          const isMatch = bcrypt.compareSync(password, user.password)

          if (!isMatch) {
              // for security reasons (the user doesn't exists or the password is incorrect)
              // it is good to send the same error message
              res.status(401).json({ errors: [{ msg: "Invalid Credentials" }] })
              return
          }

          // check if verified
          if (user.verified) {
              /// return jsonwebtoken to be used with protected routes ///
              const payload = {
                  user: {
                      // the id is automatically generated by MongoDB
                      id: user.id
                  }
              }


              // the following will return a token generated for the user
              jwt.sign(payload,
                  process.env.USER_JWT_SECRET,
                  // ! Do Not Forget To transform it Back To 3600s In Production
                  { expiresIn: 2630000 },
                  (err, token) => {
                      if (err) throw err
                      const s = {
                          token: token,
                          userData: {
                              id: user.id
                          }
                      }
                      res.status(201).json(s)
                      return
                  })
          } else {
              res.status(403).json({ errors: [{ msg: "Email Unverified" }] })
              return
          }

      } catch(err) {
          console.error(err.message)
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


// @route   POST /api/users
// @desc    register new user
// @access  Public

app.post(
  '/api/users',
  [
    check("email", "Please include a valid email").isEmail(),
    check("password", "Password should be of 6 characters or more").isLength({ min:6 })
  ],
  async (req, res) => {
      const errors = validationResult(req)
      if (!errors.isEmpty()) {
          return res.status(400).json({ errors: errors.array() })
      }
      // destructuring the request
      const { email, password } = req.body
      try {
          let user = await User.findOne({ email })

          if (user) {
              // 401 is not the right response, but this is just a temporary solution
              res.status(401).json({ errors: [{ msg: "User already exists" }] })
          }

          /// creating the user ///
          user = new User({
              email: email,
              password: password
          })

          /// before saving the user to the DB, encrypt the password with bcrypt ///
          user.password = await bcrypt.hash(password, await bcrypt.genSalt(saltRounds))

          /// now save the user and the profile to the DB ///
          await user.save()
          res.status(201).send(user.id)
      } catch(err) {
          console.error(err.message)
          res.status(500).send("Server Error")
      }
})


// @route   POST api/save-pdf
// @desc    convert data to PDF
// @access  Private
app.post(
  '/api/save-pdf',
  body('html').escape().not().isEmpty().isString().trim(),
  body('filename').escape().not().isEmpty().isString().trim(),
  async function(req, res) {
      const errors = validationResult(req)
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() })
      }

      try {
        const { html, filename } = req.body

        const decodedHtml = decode(html)

        // generate a PDF file
        const browser = await puppeteer.launch();

        const page = await browser.newPage();

        await page.setContent(decodedHtml, { waitUntil: "networkidle0" });

        const pdfBuffer = await page.pdf({
          format: 'A4',
          printBackground: true,
          preferCSSPageSize: true,
        });


        await browser.close();
        res.setHeader("Content-Type", "application/pdf");
        res.setHeader("Content-Disposition", `inline; filename=${filename}`);
        res.send(pdfBuffer)

      } catch (err) {
        console.error('Error in /api/save-word:', err)
        res.status(500).json({ error: `Error converting HTML to PDF ${err.message}` })
      }

  }
)


// @route   POST api/video/summary
// @desc    summarize a single video
// @access  Private
app.post(
  '/api/video/summary',
  async function(req, res) {
    // transcript
    const { transcript, videoTitle, isCourse } = req.body;

    console.log('inside video > summary');

    const result = await getVideoSummary(transcript, videoTitle);

    // final result are in HTML string
    res.json({ content: result })
    return
})


// @route   POST api/video/notes
// @desc    handle everything else but summary
// @access  Private
app.post(
  '/api/video/notes',
  async function(req, res) {
    // transcript
    const { transcript, videoTitle, screenshot, isCourse } = req.body;

    console.log('inside video > notes')

    const { isProg, isTutorial } = await videoInfo(transcript)

    try {
      if (isProg) {
        console.log('a programming video')
        const finalRes = await handleProg(isTutorial, videoTitle, transcript, isCourse)
        res.json({ content: finalRes })
        return
      } else if (!isProg && !isTutorial) {
        console.log('not prog, but a lecture')
        const finalRe = await getHTMLLecture(transcript, videoTitle, screenshot, isCourse)
        res.json({ content: finalRe })
        return
      } else {
        console.log('not prog, but a tutorial')
        const finalResult = await getHTMLTutorial(transcript, videoTitle, screenshot, isCourse)
        res.json({ content: finalResult })
        return
      }
    } catch (err) {
      res.status(500).json({ error: `Interanl server error ${err.message}` })
    }

})


// @route   POST api/get-audio
// @desc    get the summary/notes' audio
// @access  Private
app.post(
  '/api/get-audio',
  async function(req, res) {
    try {

      // transcript
      const { content } = req.body;

      const contentBef = parse(content)

      const contentFormatted = contentBef.rawText
      const finalTxt = contentFormatted.replace(/^\n+|\n+$/g, '').replace(/\n+/g, '\n')

      // This example requires environment variables named "SPEECH_KEY" and "SPEECH_REGION"
      const speechConfig = sdk.SpeechConfig.fromSubscription(process.env.AZURE_SPEECH_KEY, process.env.AZURE_SPEECH_REGION);
      speechConfig.speechSynthesisOutputFormat = sdk.SpeechSynthesisOutputFormat.Audio48Khz192KBitRateMonoMp3
      // The language of the voice that speaks.
      speechConfig.speechSynthesisVoiceName = "en-US-JaneNeural";
      // Create the speech synthesizer.
      var synthesizer = new sdk.SpeechSynthesizer(speechConfig, null);

      // Start the synthesizer and wait for a result.
      synthesizer.speakTextAsync(
          finalTxt,
          result => {
              // Interact with the audio ArrayBuffer data
              const audioData = result.audioData;
              // convert to base64
              const buffer = Buffer.from(audioData);
              const base64 = buffer.toString('base64');
              res.json({ audio64: base64 })
              synthesizer.close();
              return
          },
          error => {
              console.log(error);
              synthesizer.close();
      });

    } catch (error) {
      console.error('Error in /api/get-audio:', error);
      res.status(500).send('Something went wrong in /api/get-audio');
    }

});


/////////// reusable functions ///////////

async function getVideoSummary (transcript, videoTitle, isCourse) {
  const summaryCompletion = await openai.createChatCompletion({
    model: "gpt-3.5-turbo",
    messages: [
      {
        role: "system", content: "You are a helpful assistant that write engaging summaries into VERY SHORT paragraphs, and transform the results into HTML format."
      },
      {
        role: "user", content: `write an engaging summary for the following into short paragraphs like you are talking to the reader. The results should be in HTML string format: - There are two types of search engines or directories for customer reviews. The first is general search engines. Now, this is Google, Bing, Yahoo. You've probably searched for something on one of these search engines. The next is industry-specific directories. For example, Yelp, which is for food or restaurants, Healthgrades, which is for doctors, Avvo, which is for lawyers, and TripAdvisor, which is for travel. So, since I just mentioned TripAdvisor, let's go over here and we're going to look at a hotel I recently stayed at, and that is Holiday Inn Express Hotel and Suites Carpinteria, and what is interesting is a lot of the search directories are structured pretty similarly. So, at the very top of this, we see contact information and location for this particular hotel. Then, we see the overview. We see that this has four out of five stars, which is a pretty good ranking and review for this location, based off of TripAdvisor's overall ranking system. So, there are several amenities that this particular location has, and that is free Wi-Fi, free parking, breakfast included. Now, a fun thing that TripAdvisor does, and quite a few of these directories also do, is they pick out trending keywords, and they highlight those keywords for people who are searching for different kinds of businesses. Now, this particular location has two really fun keywords that trend, and that is pancake machine. In fact, I tried to figure out how this pancake machine worked, and secret, I couldn't, but I'm sure if you ever stay at this location, you will love the pancake machine and definitely figure it out. Are there any special features about your business that you'd want to highlight? If you call them out for your customer, they may be more likely to end up helping your brand stand out, when others search for you. It's a good practice to try searching with an industry specific directory, and a general search engine for your brand or business to see if any special comments or reviews appear on either platform, like the pancake machine.`
      },
      {
        role: "assistant", content: `<div>
        <div>
           <p>There are two types of directories you can use: general search engines like Google, Bing, and Yahoo, or industry-specific directories like Yelp for food, Healthgrades for doctors, Avvo for lawyers, and TripAdvisor for travel.</p>
        </div>
        <div>
           <p>Let's take TripAdvisor as an example. The speaker recently stayed at the Holiday Inn Express Hotel and Suites Carpinteria, and notes that the structure of search directories is quite similar. The overview includes the hotel's contact information, location, rating, and amenities like free Wi-Fi, parking, and breakfast.</p>
        </div>
        <div>
           <p>What's interesting is that directories like TripAdvisor also highlight trending keywords to make it easier for people to find businesses. For instance, the Holiday Inn Express Hotel and Suites Carpinteria has two fun keywords that trend: "pancake machine". The speaker admits to not being able to figure out how it works, but recommends checking it out for yourself when you stay there.</p>
        </div>
        <div>
           <p>If you're a business owner, the speaker recommends highlighting any special features about your business to make it stand out when people search for you. It's a good practice to try searching with both industry-specific directories and general search engines to see if any special comments or reviews appear on either platform. So, next time you're looking for customer reviews, don't forget to try out these directories and see what's trending!</p>
        </div>
      </div>`
      },
      {
        role: "user", content: `write an engaging summary for the following into short paragraphs like you are talking to the reader. The results should be in HTML string format: ` + transcript
      },
    ],
  })

  // return the final results
  const res = summaryCompletion.data.choices[0].message.content
  const finalRes = isCourse ? `<h3>${videoTitle}</h3>\n` + res : `<h1>${videoTitle}</h1>\n` + res
  return finalRes

}


// get the video's info
async function videoInfo(vidTran) {
  const openai = new OpenAIApi(configuration)
  // this is to know if it's a tutorial or a lecture
  // And whether it is about programming
  const completion = await openai.createChatCompletion({
    model: "gpt-3.5-turbo",
    messages: [
      {
        role: "system", content: "You are a helpful assistant that can recognize whether a transcript is a tutorial or a lecture, and whether it is about programming or not."
      },
      {
        role: "user", content: "Answer the following two questions with 'Yes' or 'No'. 1. Is the following a tutorial? 2. Is the following about programming? '- [Narrator] There's no doubt working with influencers is on the rise. According to a report by Business Insider, by 2022, companies will be spending as much as $15 billion on influencer marketing. Today, nearly 80% of influencer programs happen in Instagram. Yet the landscape and rules of engagement continue to change and it's difficult finding the influencers who are a good fit for your audience and brand. Are you looking for reach or to build awareness? If you have the budget, you may want to consider digital or traditional stars, or maybe you'd rather have a closer relationship with your influencers. That's where a more niche group like micro-influencers come in. Micro-influencers, the most popular influencer group on Instagram have fewer than 10,000 followers. Because of that, their rates are generally lower than stars, and this provides an opportunity for smaller brands who may not have the budgets to afford a celebrity to develop an effective influencer plan. Now, if you want to get even more niche, there's a category called nano-influencers who have between 1,000 to 5,000 followers. Nano-influencers usually cost even less than micro-influencers because their reach is lower and they're often more specialized. Nano-influencers are also closely connected with their followers, who consider them almost like a friend, and that can result in higher trust and engagement. But because they may be hobbyists, it could take more time to manage them. And because they have less than 10,000 followers, nano-influencers aren't able to share a link right from their post, only in their bio, and that makes attribution and ROI a bit harder for brands. And then, there are the bots or virtual influencers like Lil Miquela. Lil Miquela has 1.6 million followers on Instagram, has done promotions for brands like Prada and Calvin Klein, and released songs on Spotify even though she, it, is just a computer-generated creation owned by a company. Avatars like these are becoming more popular at engaging with consumers. And in an era of deep fake videos and concerns around privacy and ethics, we need to ask ourselves whether virtual influencers should be forced to disclose they're not human in the same way human influencers must disclose payment. So if you are a brand that wants to work with influencers, how would you get started? First, establish your budget and whether you're going for reach or niche. Then, determine what success looks like and develop metrics tied to business goals. When you choose influencers to work with, be sure your brand values are aligned with theirs. Define the scope of the partnership but also give influencers the freedom to be creative. They know their audience better than you. And while Instagram is still the most popular platform, remember, you can also create programs on YouTube, Pinterest, Twitter, and even an influencer's blog.'"
      },
      {
        role: "assistant", content: "1. No.\n2. No."
      },
      {
        role: "user", content: "Answer the following two questions with 'Yes' or 'No'. 1. Is the following a tutorial? 2. Is the following about programming? " + vidTran
      },
    ],
  })

  const qs = completion.data.choices[0].message.content.split(/\r?\n/)
  const isTutorial = qs[0].substring(3, 5) === 'No' ? false : true
  const isProg = qs[1].substring(3, 5) === 'No' ? false : true

  return {
    isTutorial: isTutorial,
    isProg: isProg
  }
}


// handle programming related content
async function handleProg(isTutorial, vidTitle, videoTrans, isCourse) {

  if (isTutorial) {
    const completion = await openai.createChatCompletion({
      model: "gpt-3.5-turbo",
      messages: [
        {
          role: "system", content: "You are a helpful assistant that convert and simplify programming video transcripts into step-by-step written tutorials, and you write code examples and explain them with a very simple language. And you convert the results to valid HTML"
        },
        {
          role: "user", content: "Convert and simplify the following programming video transcript into a step-by-step tutorial while making sure that you give simple examples and explain them thoroughly. The final result should in HTML format with only DIV tag as the parent: - [Instructor] So let's see how we'd go about creating and using arrays in Java. So I've got a class here called ArrayExamples with a main method in it, and I'm just going to stick all my code in this main method. So to create an array, the first thing I need to do, is I need to put the type of elements that's going to be in it. So to create an array of strings, for example, I would put the word String, followed by a pair of square brackets, and then the name of my array. So I'm going to call this one weekdays. And then after the equal sign, I put 'new String' and then another pair of square brackets and a semi-colon. And inside these square brackets, I need to put how many elements are going to be inside the array and this won't change. So it will be the same for the whole lifetime of the array. So there are seven weekdays, so I'm going to put the number seven. I'm going to print this out now and see what it gives me. So if I do System.out.println, I'm using an IntelliJ shortcut there so if you do, S-O-U-T and press tab, it will complete that automatically for you. And then I'm going to pass in the name of the array, which is weekdays. And I'm going to run this now and see what happens. So to run it, I can click on this green arrow here and do 'Run ArrayExamples.main().' And I can see it prints out this Ljava.lang.String and some hash code, which isn't particularly useful. So instead of passing in weekdays, I'm going to do Arrays.toString() and then pass in the name of the array, so weekdays. And make sure that you have the import statements at the top. So IntelliJ added it automatically, but just make sure you've got the import there for the arrays.toString() method. So let's run this again and see what I get now. And it should give me a more human readable version. So now I've got an array with seven nulls in. What's happening here is when you first create an array, if you don't say what any of the values are going to be, Java will just use the default value for that type. So the default value for a string is null. So for ints it would be zero and for booleans it would be false, and thing like that. So now let's try setting some of the values. I want to set the first one to Monday. So to do that, I can do weekdays. And then in a pair of square brackets, I put the index of the elements I want to change. So to change the first value, I put the number zero, and then after the equal sign, I'm going to put the string Monday. Now I'm going to copy and paste the System.out.println and put this underneath here and run it again. And now I can see that I've got the first value as Monday and all the others are still null. So I could go through and set all the values like this so I could do weekdays one equals Tuesday, weekdays two equals Wednesday and so on. But another way to set arrays is when you create them, instead of saying how many values are going to be in it, you can say straight away, what all the values are. So let's do that with the weekdays variable. I'm going to put weekdays and I'm going to replace this array and create a whole new one. So I'm going to do 'new String' and a pair of square brackets. And then instead of putting a number in the square brackets, I'm going to put a pair of curly braces. And then inside the curly braces, I put the values that I want to be in the array. So I'm going to put Mon for Monday, Tue for Tuesday, Wed for Wednesday, and I'll stop there because I'm lazy and I can't be bothered to write all seven. So let's copy the System.out.println again and put that underneath and rerun it. And now I've got an array with three values in, Monday, Tuesday, Wednesday. So there are two different ways that you can create arrays and instantiate the values inside them. The next thing we might want to do is we might want to iterate over the array. So to do that, one thing I can do is use a for each loop. So I could do for String day in weekdays, so that's going to go through each string in the weekdays array. And let's say I want to print out weekday and then the weekday. So I'm going to do System.out.println and pass in the string 'Week day,' and then add the day to that string. So I'm going to run this again. Another way you can run the program in IntelliJ is at the top, there's a green arrow that will run the class for you. And so now I can see I've got weekday Mon, weekday Tues, weekday Wednesday. So that for each loop lets me iterate over each value in the array and access it. But I can't actually alter any of the elements when I do it like this. I need an index to keep track of them. So another way to iterate over them is using a for loop with an index. So I can do for and then int i equals zero for the index. And then i is smaller than weekdays.length. I don't want it to ever be equal to weekdays.length because that would give me an out of bounds exception because the index starts at zero, and then i++. And so let's say I want to make every value in the array, all in capital letters. So to get each element, I'm going to do weekdays and then pass in i for the index and I can do equals weekdays i and I'm going to call the toUpperCase() method. So this should make every element in the array, all in capitals. I'm going to copy and paste the System.out.println again and put this underneath. So let's see what happens when I run it now. And now I can see that every element in the array is all to uppercase. So that's how you'd iterate over the array, if you wanted to make some changes to the elements inside it."
        },
        {
          role: "assistant", content:`<div>
          <p>In this tutorial, we will learn how to create and use arrays in Java. We will begin by creating an array of strings to store the weekdays. We will then print out the array, modify its values, and iterate through its elements.</p>
          <h3>Creating an array</h3>
          <p>To create an array, we need to specify the type of elements it will contain. For example, to create an array of strings, we can use the following syntax:</p>
          <pre><code>String[] weekdays = new String[7];</code></pre>
          <p>This creates an array of strings named weekdays with seven elements. The new keyword allocates memory for the array, and the number inside the square brackets specifies its size. By default, the values in the array are null. To set the value of an element, we can use the index inside square brackets. For example, to set the first element to 'Monday', we can use the following syntax:</p>
          <pre><code>weekdays[0] = "Monday";</code></pre>
          <h3>Printing an array</h3>
          <p>We can print out the array using the Arrays.toString() method. To use this method, we need to import the java.util.Arrays package. For example:</p>
          <pre><code>
            import java.util.Arrays;
            String[] weekdays = new String[7];
            System.out.println(Arrays.toString(weekdays));
          </code></pre>
          <p>This code will print [ [null, null, null, null, null, null, null] ].</p>
          <h3>Setting values in an Array</h3>
          <p>Alternatively, we can initialize the array with values when we create it. For example:</p>
          <pre><code>
            String[] weekdays = {"Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"};
          </code></pre>
          <p>Or you can specify the index of the element you want to change. For example:</p>
          <pre><code>
            String[] weekdays = new String[7];
            weekdays[0] = "Monday";
          </code></pre>
          <p>This code sets the first element of the weekdays array to "Monday".</p>
          <h3>Iterate over an Array</h3>
          <p>We can iterate through the array using a for-each loop. This loop lets us access each element of the array one by one, but we cannot modify the elements. For example:</p>
          <pre><code>
            String[] weekdays = {"Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"};
            for (String day : weekdays) {
              System.out.println(day);
            }
          </code></pre>
          <p>This code will print:</p>
          <pre><code>
            Monday
            Tuesday
            Wednesday
            Thursday
            Friday
            Saturday
            Sunday
          </code></pre>
          <p>We can also iterate through the array using a for loop with an index. This loop lets us modify the elements. For example:</p>
          <pre><code>
            for (int i = 0; i < weekdays.length; i++) {
              weekdays[i] = "Day " + i;
              System.out.println("Weekday " + i + " is " + weekdays[i]);
            }
          </code></pre>
          <p>This loop starts from 0 and continues until it reaches the length of the array. We can modify the value of an element using the index <code>i</code> like follow: <code>weekdays[i] = "Day" + i;</code> The <code>weekdays.length</code> gives the length of the array. It will print the following:
        <code>
          Weekday 0 is Day 0
          Weekday 1 is Day 1
          Weekday 2 is Day 2
          Weekday 3 is Day 3
          Weekday 4 is Day 4
          Weekday 5 is Day 5
          Weekday 6 is Day 6
        </code>
        </div>`
        },
        {
          role: "user", content: "Convert and simplify the following programming video transcript into a step-by-step tutorial while making sure that you give simple examples and explain them thoroughly. The final result should in HTML format with only DIV tag as the parent: " + videoTrans
        },
      ],
    })

    // return the final results
    const r = completion.data.choices[0].message.content
    const rFormated = isCourse ? `<h3>${vidTitle}</h3>\n` + r : `<h1>${vidTitle}</h1>\n` + r
    return { content: rFormated }

  } else {
    const completion = await openai.createChatCompletion({
      model: "gpt-3.5-turbo",
      messages: [
        {
          role: "system", content: "You are a helpful assistant that convert lectures to comprehensive notes with easy-to-understand code examples. And you format the result in HTML."
        },
        {
          role: "user", content: "Convert the following programming-related lecture to comprehensive notes with easy-to-understand code examples: - [Instructor] There are three different types of design patterns. One is creational, the other is structural, and another is behavioral. We use creational design patterns to build objects systematically. The main benefit behind creation of patterns lies in their flexibility. For example, different subtypes of objects from the same class can be created at runtime, when you use creational patterns. We use structural patterns to establish relationships between software components in particular settings or configurations. The goal here is to satisfy specific functional or non-functional requirements. Functional requirements refer to what software does. Non-functional requirements are how well it completes its job. The question of how fast or slow software functions belongs to the nonfunctional domain. Different requirements lead to various structure's implemented instructional patterns. Behavioral patterns are the best practices of how you make your objects interact with each other. The focus here is defining the protocols between these objects when trying to work together to accomplish a common goal. Some core object oriented mechanisms or concepts are foundations for developing design patterns. Whether creational, structural, or behavioral. In the creational patterns, Polymorphism is often in use. Structural patterns take advantage of inheritance, a lot. Behavioral patterns, heavily use methods and their signatures. Interfaces are at work across all these different types of design patterns. I'll explain each of these concepts in dedicated lessons. Knowing the design pattern types is helpful because it allows you to locate the design pairings you need, quickly."
        },
        {
          role: "assistant", content: `<div>
          <h3>Design Patterns</h3>
          <p>Design patterns are standardized solutions to common problems that software developers face when writing code. There are three different types of design patterns: creational, structural, and behavioral.</p>
          <h3>Creational Patterns</h3>
          <p>Creational design patterns help developers build objects systematically. These patterns offer flexibility in creating different subtypes of objects from the same class at runtime. For example, imagine a pizza restaurant that uses creational design patterns to build different types of pizzas using the same set of ingredients. Here's a short and simple example of the Singleton design pattern in Java, which is a creational design pattern. The Singleton pattern ensures that a class has only one instance and provides a global point of access to that instance.
          <pre><code>
            public class Singleton {

              // Declare a private static instance of the class
              private static Singleton instance;

              // Private constructor to prevent instantiation from other classes
              private Singleton() {
              }

              // Public method to access the unique instance of the class
              public static Singleton getInstance() {
                if (instance == null) {
                    instance = new Singleton();
                }
                return instance;
              }
            }

            public class Main {
              public static void main(String[] args) {
                // Get the unique instance of the Singleton class
                Singleton singletonInstance1 = Singleton.getInstance();
                Singleton singletonInstance2 = Singleton.getInstance();
                // Verify that both instances are the same

                System.out.println("singletonInstance1 and singletonInstance2 are the same: " + (singletonInstance1 == singletonInstance2));
              }
            }
          </code></pre>\n
          In this example, the <code>Singleton</code> class has a private constructor and a private static instance of itself. The <code>getInstance()</code> method ensures that only one instance of the <code>Singleton<code> class is created, and it is used as the global point of access. In the <code>Main</code> class, we obtain two instances of the <code>Singleton</code> class and verify that they are the same, demonstrating the <code>Singleton<code> pattern's purpose.
          </p>
          <h3>Structural Patterns</h3>
          <p>Structural design patterns help establish relationships between software components in particular settings or configurations. The goal here is to satisfy specific functional or non-functional requirements. Functional requirements refer to what the software does, while non-functional requirements refer to how well it does it. A good example of a structural pattern is the Model-View-Controller (MVC) pattern, which separates the concerns of user interface, data, and control logic in software development.</p>
          <h3>Behavioral Patterns</h3>
          <p>Behavioral design patterns are best practices for how to make objects interact with each other. The focus here is on defining the protocols between these objects when working together to achieve a common goal. One common behavioral pattern is the Observer pattern, where objects are notified of any changes to another object's state.</p>
          <p>Polymorphism is often used in creational patterns. Inheritance is heavily used in structural patterns, while methods and their signatures are the focus of behavioral patterns. Interfaces are at work across all these different types of design patterns.</p>
          <p>Knowing the different types of design patterns is helpful because it allows developers to quickly locate the design pairings they need to solve specific software development problems.</p>
          </div>`
        },
        {
          role: "user", content: "Convert the following programming-related lecture to comprehensive notes with easy-to-understand code examples. The final result should in HTML format with only DIV tag as the parent: " + videoTrans
        },
      ],
    })

    // return the final results
    const r = completion.data.choices[0].message.content
    const rFormated = isCourse ? `<h3>${vidTitle}</h3>\n` + r : `<h2>${vidTitle}</h2>\n` + r
    return { content: rFormated }
  }
}


// get the HTML version of the lecture inputted
// and the keyPhrases(for screenshots) in an array
async function getHTMLLecture(lecture, videoTitle, shots, isCourse) {

  if (!shots) {
    const lectureCompletion = await openai.createChatCompletion({
      model: "gpt-3.5-turbo",
      messages: [
          {
            role: "system", content: "You are a helpful assistant that takes engaging and comprehensive notes from video transcripts and formulate them into paragraphs. And your return the final results in an appropriate HTML format."
          },
          {
            role: "user", content: "Write an engaging and comprehensive notes in simple language for the following and formulate them into short paragraphs. The final result should be in an appropriate HTML format: - There are two types of search engines or directories for customer reviews. The first is general search engines. Now, this is Google, Bing, Yahoo. You've probably searched for something on one of these search engines. The next is industry-specific directories. For example, Yelp, which is for food or restaurants, Healthgrades, which is for doctors, Avvo, which is for lawyers, and TripAdvisor, which is for travel. So, since I just mentioned TripAdvisor, let's go over here and we're going to look at a hotel I recently stayed at, and that is Holiday Inn Express Hotel and Suites Carpinteria, and what is interesting is a lot of the search directories are structured pretty similarly. So, at the very top of this, we see contact information and location for this particular hotel. Then, we see the overview. We see that this has four out of five stars, which is a pretty good ranking and review for this location, based off of TripAdvisor's overall ranking system. So, there are several amenities that this particular location has, and that is free Wi-Fi, free parking, breakfast included. Now, a fun thing that TripAdvisor does, and quite a few of these directories also do, is they pick out trending keywords, and they highlight those keywords for people who are searching for different kinds of businesses. Now, this particular location has two really fun keywords that trend, and that is pancake machine. In fact, I tried to figure out how this pancake machine worked, and secret, I couldn't, but I'm sure if you ever stay at this location, you will love the pancake machine and definitely figure it out. Are there any special features about your business that you'd want to highlight? If you call them out for your customer, they may be more likely to end up helping your brand stand out, when others search for you. It's a good practice to try searching with an industry specific directory, and a general search engine for your brand or business to see if any special comments or reviews appear on either platform, like the pancake machine."
          },
          {
            role: "assistant", content: `<div>
              <p>There are two types of search engines or directories for customer reviews. The first type is general search engines, such as Google, Bing, and Yahoo, which most people have used before. The second type is industry-specific directories, such as Yelp for food and restaurants, Healthgrades for doctors, Avvo for lawyers, and TripAdvisor for travel. The speaker uses TripAdvisor as an example and looks at a hotel they recently stayed at called Holiday Inn Express Hotel and Suites Carpinteria.</p>\n
              <p>The speaker notes that many search directories are structured similarly. For this hotel, the contact information and location are displayed at the top of the page, followed by an overview of the hotel's amenities. The hotel has a four out of five stars ranking, which is considered pretty good according to TripAdvisor's overall ranking system. Some of the amenities the hotel offers include free Wi-Fi, free parking, and breakfast included.\nThe speaker also mentions that TripAdvisor and other directories often highlight trending keywords for people searching for different types of businesses. In this case, the hotel has two fun trending keywords - "pancake machine." The speaker tried to figure out how the pancake machine worked but couldn't, but suggests that anyone who stays at the hotel should try it out.</p>\n
              <p>The speaker advises businesses to call out any special features they have to their customers as this may help their brand stand out when others search for them. It's a good idea to search for your business using both an industry-specific directory and a general search engine to see if any special comments or reviews appear on either platform.</p>
            </div>`
          },
          {
            role: "user", content: "Write an engaging and comprehensive notes in simple language for the following and formulate them into short paragraphs. The final result should be in an appropriate HTML format: " + lecture
          },
      ],
    })
    const r = lectureCompletion.data.choices[0].message.content
    return isCourse ? `<h3>${videoTitle}</h3>\n` + r : `<h1>${videoTitle}</h1>\n` + r

  } else {

    const lectureCompletion = await openai.createChatCompletion({
      model: "gpt-3.5-turbo",
      messages: [
          {
            role: "system", content: "You are a helpful assistant that takes comprehensive and engaging notes from video transcripts and formulate them into VERY SHORT paragraphs."
          },
          {
            role: "user", content: "Write comprehensive and engaging notes in simple language for the following and formulate them into VERY SHORT paragraphs: - There are two types of search engines or directories for customer reviews. The first is general search engines. Now, this is Google, Bing, Yahoo. You've probably searched for something on one of these search engines. The next is industry-specific directories. For example, Yelp, which is for food or restaurants, Healthgrades, which is for doctors, Avvo, which is for lawyers, and TripAdvisor, which is for travel. So, since I just mentioned TripAdvisor, let's go over here and we're going to look at a hotel I recently stayed at, and that is Holiday Inn Express Hotel and Suites Carpinteria, and what is interesting is a lot of the search directories are structured pretty similarly. So, at the very top of this, we see contact information and location for this particular hotel. Then, we see the overview. We see that this has four out of five stars, which is a pretty good ranking and review for this location, based off of TripAdvisor's overall ranking system. So, there are several amenities that this particular location has, and that is free Wi-Fi, free parking, breakfast included. Now, a fun thing that TripAdvisor does, and quite a few of these directories also do, is they pick out trending keywords, and they highlight those keywords for people who are searching for different kinds of businesses. Now, this particular location has two really fun keywords that trend, and that is pancake machine. In fact, I tried to figure out how this pancake machine worked, and secret, I couldn't, but I'm sure if you ever stay at this location, you will love the pancake machine and definitely figure it out. Are there any special features about your business that you'd want to highlight? If you call them out for your customer, they may be more likely to end up helping your brand stand out, when others search for you. It's a good practice to try searching with an industry specific directory, and a general search engine for your brand or business to see if any special comments or reviews appear on either platform, like the pancake machine."
          },
          {
            role: "assistant", content: `There are two types of search engines or directories for customer reviews. The first type is general search engines, such as Google, Bing, and Yahoo, which most people have used before. The second type is industry-specific directories, such as Yelp for food and restaurants, Healthgrades for doctors, Avvo for lawyers, and TripAdvisor for travel. The speaker uses TripAdvisor as an example and looks at a hotel they recently stayed at called Holiday Inn Express Hotel and Suites Carpinteria.\n The speaker notes that many search directories are structured similarly. For this hotel, the contact information and location are displayed at the top of the page, followed by an overview of the hotel's amenities. The hotel has a four out of five stars ranking, which is considered pretty good according to TripAdvisor's overall ranking system. Some of the amenities the hotel offers include free Wi-Fi, free parking, and breakfast included.\n The speaker also mentions that TripAdvisor and other directories often highlight trending keywords for people searching for different types of businesses. In this case, the hotel has two fun trending keywords - "pancake machine." The speaker tried to figure out how the pancake machine worked but couldn't, but suggested that anyone who stays at the hotel should try it out.\n The speaker advises businesses to call out any special features they have to their customers as this may help their brand stand out when others search for them. It's a good idea to search for your business using both an industry-specific directory and a general search engine to see if any special comments or reviews appear on either platform.`
          },
          {
            role: "user", content: "Write comprehensive and engaging notes in simple language for the following and formulate them into VERY SHORT paragraphs: " + lecture
          },
      ],
    })

    const videoLecture = lectureCompletion.data.choices[0].message.content

    // this is just for the bingAIClient
    const fractured = videoLecture.split('\n')
    const wrappedStrings = fractured.map(str => `(${str})`).join(' ')

    console.log(wrappedStrings)

    // now we are going to match the right keywords used by the speaker to the right steps
    let response = await bingAIClient.sendMessage(`I'll give you lecture notes divided into paragraphs which are ENCLOSED within parentheses. Your task is to place the EXACT FEW WORDS used by the speaker after which it is appropriate to take a screenshot that encapsulates the meaning of the paragraph enclosed in the parentheses. THE FEW WORDS SHOULD BE WRAPPED IN PARENTHESES. This is the lecture notes: ${wrappedStrings}. And this is the speech: ${lecture}`, {
        // (Optional) Set a conversation style for this message (default: 'balanced')
        toneStyle: 'precise', // or creative, precise, fast
    });

    const theRes = response.response

    const regex = /\((?:\.\.\.)?(.*?)(?:\.\.\.)?\)/g;

    const words = [];
    let match;

    while ((match = regex.exec(theRes)) !== null) {
        const word = match[1].replace(/"/g, '');
        words.push(word);
    }

    let keyPhrases = words.map(el => el.replace(/^\.+/, ''))

    if (keyPhrases.length === 0) {
      keyPhrases = theRes.match(/"(.*?)"/g).map(quote => quote.slice(1, -1));
    }

    function insertImages(text, images) {
        const paragraphs = text.split('\n');
        const updatedParagraphs = paragraphs.map((paragraph, index) => {
            const imgSrc = images[index];
            if (imgSrc) {
              return `${paragraph}<img src=${imgSrc} alt='' />\n`;
            } else {
              return paragraph;
            }
        });

        const updatedText = updatedParagraphs.join('\n');
        return updatedText
    }

    const lectureWithImgs = insertImages(videoLecture, keyPhrases)

    // this is for the tutorials
    const htmlCompletion = await openai.createChatCompletion({
        model: "gpt-3.5-turbo",
        messages: [
          {
            role: "system", content: "You are a helpful assistant that converts notes to an appropriate HTML format."
          },
          {
            role: "user", content: `Convert the following notes to an appropriate HTML format. Don't add <h2> tag or anything and use just <div> and <p> tags: There are two types of search engines or directories for customer reviews. The first type is general search engines, such as Google, Bing, and Yahoo, which most people have used before. The second type is industry-specific directories, such as Yelp for food and restaurants, Healthgrades for doctors, Avvo for lawyers, and TripAdvisor for travel. The speaker uses TripAdvisor as an example and looks at a hotel they recently stayed at called Holiday Inn Express Hotel and Suites Carpinteria.<img src="breakfast included." alt='' />\n The speaker notes that many search directories are structured similarly. For this hotel, the contact information and location are displayed at the top of the page, followed by an overview of the hotel's amenities. The hotel has a four out of five stars ranking, which is considered pretty good according to TripAdvisor's overall ranking system. Some of the amenities the hotel offers include free Wi-Fi, free parking, and breakfast included. <img src="It doesn't have to be that way" alt='' /> \n The speaker also mentions that TripAdvisor and other directories often highlight trending keywords for people searching for different types of businesses. In this case, the hotel has two fun trending keywords - "pancake machine." The speaker tried to figure out how the pancake machine worked but couldn't, but suggested that anyone who stays at the hotel should try it out. <img src="the TripAdvisor is right." alt='' /> \n The speaker advises businesses to call out any special features they have to their customers as this may help their brand stand out when others search for them. It's a good idea to search for your business using both an industry-specific directory and a general search engine to see if any special comments or reviews appear on either platform. <img src="New customers have to be there" alt='' />`
          },
          {
            role: "assistant", content: `<div>
            <div>
               <p>There are two types of search engines or directories for customer reviews. The first type is general search engines, such as Google, Bing, and Yahoo, which most people have used before. The second type is industry-specific directories, such as Yelp for food and restaurants, Healthgrades for doctors, Avvo for lawyers, and TripAdvisor for travel. The speaker uses TripAdvisor as an example and looks at a hotel they recently stayed at called Holiday Inn Express Hotel and Suites Carpinteria.</p>
            <img src="breakfast included." alt='' />
            </div>
            <div>
               <p>The speaker notes that many search directories are structured similarly. For this hotel, the contact information and location are displayed at the top of the page, followed by an overview of the hotel's amenities. The hotel has a four out of five stars ranking, which is considered pretty good according to TripAdvisor's overall ranking system. Some of the amenities the hotel offers include free Wi-Fi, free parking, and breakfast included.</p>
             <img src="It doesn't have to be that way" alt='' />
            </div>
            <div>
               <p>The speaker also mentions that TripAdvisor and other directories often highlight trending keywords for people searching for different types of businesses. In this case, the hotel has two fun trending keywords - "pancake machine." The speaker tried to figure out how the pancake machine worked but couldn't, but suggested that anyone who stays at the hotel should try it out. </p>
             <img src="the TripAdvisor is right." alt='' />
            </div>
            <div>
               <p>The speaker advises businesses to call out any special features they have to their customers as this may help their brand stand out when others search for them. It's a good idea to search for your business using both an industry-specific directory and a general search engine to see if any special comments or reviews appear on either platform. </p>
             <img src="New customers have to be there" alt='' />
            </div>
          </div>`
          },
          {
            role: "user", content: `Convert the following notes to an appropriate HTML format: ` + lectureWithImgs
          },
        ],
    })

    const finalLectureWithImages = htmlCompletion.data.choices[0].message.content
    const lecWithImgs = `<h1>${videoTitle}</h1>\n` + finalLectureWithImages

    return { lecWithImgs, keyPhrases }
  }

}

// get the HTML version of the tutorial inputted
// and the keyPhrases(for screenshots) in an array
async function getHTMLTutorial(tutorial, videoTitle, shots, isCourse) {

  if (!shots) {
    // this is for the tutorials
    const tutorialCompletion = await openai.createChatCompletion({
      model: "gpt-3.5-turbo",
      messages: [
        {
          role: "system", content: "You are a helpful assistant that turns a video transcript into a step-by-step written tutorial, and you return the results in an appropriate HTML format."
        },
        {
          role: "user", content: `Turn the following video transcript into a step-by-step written tutorial (numbered) while explaining each step. The final result should be in an appropriate HTML format: [Instructor] In this movie, we're going to assign a so-called radial gradient to the central circle. All right, so first thing you want to do is select that circle with the black arrow tool and then again switch to the Gradient Tool, which actually looks like a little gradient. And then all you need to do is click inside of that circle in order to apply the last applied gradient, which happens to be that three-color linear gradient. And when I say linear gradient, I mean that the colors transition in a straight line. When you're working with a radial gradient, the colors transition in concentric circles. All right, now these aren't the colors I want, so I'll double-click on that first color stop, the one over on the left-hand side, and I'll change its color to this very dark shade of blue that begins R=27. And then I'll grab the second color stop right there, and I'll get rid of it by dragging it down off of the gradient annotator. Now I'll double-click on the last color stop, the one over on the right-hand side, and I'll change its color to white. All right, now we want to switch the style of gradient from linear to radial. And you do that by going over here to the Properties panel. Notice this little Gradient area right here. It features three types of gradients. So we've got linear, which is selected right now. We have radial. And we have freeform, which I'll show you in the next movie. But for now, just go ahead and click on radial. All right, that's the opposite effect of what I'm looking for. I don't want the gradient to go from dark blue in the center to white on the outside. I want it to go from white on the inside to dark blue on the outside. And to make that switch, go ahead and click on the dot dot dot icon down here in the bottom right corner of the gradient area. And then click on this icon right here, Reverse Gradient. And that will go ahead and swap the colors, as we're seeing here. All right, now in addition to being able to scale the gradient by dragging that square and rotate it by dragging slightly beyond the square, you also have the option of changing the center of the gradient relative to the outside edges. And you do that by dragging this little tiny black circle. So make sure that you're not seeing the pointing finger. You want to see the black arrowhead. And then drag this guy up and out like so. And notice what's happening here. As I was saying, a radial gradient transitions in concentric circles. And so what's happening is we're starting with very tiny white circles and then making them gradually larger, but the colors are transitioning much more quickly in the top left corner of the shape as opposed to this big area in the bottom right region. All right, now if you want the colors to transition at exactly 45 degrees, which is what I'm looking for, then move your cursor slightly beyond that square around the outside edge of the circle. And then as you drag, press and hold the Shift key like so. And that will constrain the angle of the gradient to the nearest equivalent of 45 degrees. All right, now I want to add a kind of dark edge, so I'm going to add a couple of additional color stops, not by clicking below the gradient annotator like I did in the previous movie, but rather by duplicating an existing color stop. And you do that by pressing and holding the alt key or the opt key on the Mac and dragging this outside color stop in this case, and that will make a duplicate of it. All right, I'll go ahead and double-click on that color stop in order to bring up the swatches, and I'll change the color to black. And this time I'm looking for a location value of 93%, after which I'll press the Enter key or the Return key on the Mac to accept that change. And now I want the colors to transition back to that shade of blue, so I'll once again press the Alt key or the Option key on the Mac and drag that blue color stop along the outside edge inward like so in order to make yet another copy of it. And then I'll double-click on it. I'm not interested in changing the color. It's fine as is. I am interested in changing the location value to 86%, after which point I'll press the Enter key or the Return key on the Mac to accept that change. And you now what? Come to think of it, I got the colors wrong, but this is a good opportunity for me to show you a different way to work. Notice that this color stop right here is selected, and it corresponds to this fill option here inside the Appearance section of the Properties panel. And so another way to change that color is to click on that color swatch right there and change it to the next lightest shade of blue, is what I'm looking for, the one that begins R=46. And now I'll go ahead and click off the panel to dismiss it. Then I'll select this guy along the outer edge. I'll click on that Fill swatch once again and select the next lighter shade of blue. And then I'll click off it once again. Go ahead and select that black color stop. Click on the Fill swatch. And then select the darkest shade of blue, the one that begins R=27, after which I'll press the Enter key or the Return key on the Mac to accept that change. And then I'll switch back to the black arrow selection tool up here at the top of the tool box. And finally, I'll go up to the Select menu and choose Deselect in order to entirely deselect my artwork. And that is how you create and modify a radial gradient here inside Illustrator.`
        },
        {
          role: "assistant", content: `<div>
            <h4>1. Open Adobe Illustrator and create a new document.</h4>
            <h4>2. Draw a circle using the black arrow tool.</h4>
            <h4>3. Switch to the Gradient Tool, which looks like a little gradient, and click inside the circle to apply the last applied gradient, which happens to be a three-color linear gradient.</h4>
            <h4>4. Double-click on the first color stop, located on the left-hand side, and change its color to a very dark shade of blue that begins with R=27.</h4>
            <h4>5. Grab the second color stop and get rid of it by dragging it down off of the gradient annotator.</h4>
            <h4>6. Double-click on the last color stop, located on the right-hand side, and change its color to white.</h4>
            <h4>7. Switch the style of gradient from linear to radial by going to the Properties panel and clicking on the radial gradient option.</h4>
            <h4>8. Click on the dot dot dot icon located in the bottom right corner of the gradient area and click on the Reverse Gradient icon to swap the colors, making the gradient go from white on the inside to dark blue on the outside.</h4>
            <h4>9. To change the center of the gradient relative to the outside edges, drag the tiny black circle with the black arrowhead up and out.</h4>
            <h4>10. To constrain the angle of the gradient to 45 degrees, move your cursor slightly beyond the square around the outside edge of
            the circle, and press and hold the Shift key as you drag.</h4>
            <h4>11. To add a dark edge, press and hold the Alt key (Option key on Mac) and duplicate an existing color stop by dragging it.</h4>
            <h4>12. Double-click on the duplicated color stop to bring up the swatches and change its color to black.</h4>
            <h4>13. Change the location value to 93% by pressing the Enter key (Return key on Mac).</h4>
            <h4>14. Press Alt (Option key on Mac) again and drag the blue color stop along the outside edge inward to make another copy of it.</h4>
            <h4>15. Double-click on the new blue color stop and change the location value to 86%, then press Enter (Return key on Mac).</h4>
            <h4>16. If necessary, adjust the colors by selecting the color stop and changing its color in the Fill option located in the Appearance section of the Properties panel.</h4>
            <h4>17. Switch back to the black arrow selection tool and go to the Select menu, and choose Deselect to entirely deselect your artwork.</h4>
            <p>Congratulations, you have successfully created and modified a radial gradient in Adobe Illustrator.</p>
          </div>`
        },
        {
          role: "user", content: "Turn the following video transcript into a step-by-step written tutorial (numbered) while explaining each step. The final result should be in an appropriate HTML format: " + tutorial
        },
      ],
    })

    const r = tutorialCompletion.data.choices[0].message.content

    return isCourse ? `<h3>${videoTitle}</h3>\n` + r : `<h1>${videoTitle}</h1>\n` + r

  } else {
    // this is for the tutorials
    const tutorialCompletion = await openai.createChatCompletion({
      model: "gpt-3.5-turbo",
      messages: [
        {
          role: "system", content: "You are a helpful assistant that turns a video transcript into a step-by-step written tutorial."
        },
        {
          role: "user", content: `Turn the following video transcript into a step-by-step written tutorial (numbered) while explaining each step: [Instructor] In this movie, we're going to assign a so-called radial gradient to the central circle. All right, so first thing you want to do is select that circle with the black arrow tool and then again switch to the Gradient Tool, which actually looks like a little gradient. And then all you need to do is click inside of that circle in order to apply the last applied gradient, which happens to be that three-color linear gradient. And when I say linear gradient, I mean that the colors transition in a straight line. When you're working with a radial gradient, the colors transition in concentric circles. All right, now these aren't the colors I want, so I'll double-click on that first color stop, the one over on the left-hand side, and I'll change its color to this very dark shade of blue that begins R=27. And then I'll grab the second color stop right there, and I'll get rid of it by dragging it down off of the gradient annotator. Now I'll double-click on the last color stop, the one over on the right-hand side, and I'll change its color to white. All right, now we want to switch the style of gradient from linear to radial. And you do that by going over here to the Properties panel. Notice this little Gradient area right here. It features three types of gradients. So we've got linear, which is selected right now. We have radial. And we have freeform, which I'll show you in the next movie. But for now, just go ahead and click on radial. All right, that's the opposite effect of what I'm looking for. I don't want the gradient to go from dark blue in the center to white on the outside. I want it to go from white on the inside to dark blue on the outside. And to make that switch, go ahead and click on the dot dot dot icon down here in the bottom right corner of the gradient area. And then click on this icon right here, Reverse Gradient. And that will go ahead and swap the colors, as we're seeing here. All right, now in addition to being able to scale the gradient by dragging that square and rotate it by dragging slightly beyond the square, you also have the option of changing the center of the gradient relative to the outside edges. And you do that by dragging this little tiny black circle. So make sure that you're not seeing the pointing finger. You want to see the black arrowhead. And then drag this guy up and out like so. And notice what's happening here. As I was saying, a radial gradient transitions in concentric circles. And so what's happening is we're starting with very tiny white circles and then making them gradually larger, but the colors are transitioning much more quickly in the top left corner of the shape as opposed to this big area in the bottom right region. All right, now if you want the colors to transition at exactly 45 degrees, which is what I'm looking for, then move your cursor slightly beyond that square around the outside edge of the circle. And then as you drag, press and hold the Shift key like so. And that will constrain the angle of the gradient to the nearest equivalent of 45 degrees. All right, now I want to add a kind of dark edge, so I'm going to add a couple of additional color stops, not by clicking below the gradient annotator like I did in the previous movie, but rather by duplicating an existing color stop. And you do that by pressing and holding the alt key or the opt key on the Mac and dragging this outside color stop in this case, and that will make a duplicate of it. All right, I'll go ahead and double-click on that color stop in order to bring up the swatches, and I'll change the color to black. And this time I'm looking for a location value of 93%, after which I'll press the Enter key or the Return key on the Mac to accept that change. And now I want the colors to transition back to that shade of blue, so I'll once again press the Alt key or the Option key on the Mac and drag that blue color stop along the outside edge inward like so in order to make yet another copy of it. And then I'll double-click on it. I'm not interested in changing the color. It's fine as is. I am interested in changing the location value to 86%, after which point I'll press the Enter key or the Return key on the Mac to accept that change. And you now what? Come to think of it, I got the colors wrong, but this is a good opportunity for me to show you a different way to work. Notice that this color stop right here is selected, and it corresponds to this fill option here inside the Appearance section of the Properties panel. And so another way to change that color is to click on that color swatch right there and change it to the next lightest shade of blue, is what I'm looking for, the one that begins R=46. And now I'll go ahead and click off the panel to dismiss it. Then I'll select this guy along the outer edge. I'll click on that Fill swatch once again and select the next lighter shade of blue. And then I'll click off it once again. Go ahead and select that black color stop. Click on the Fill swatch. And then select the darkest shade of blue, the one that begins R=27, after which I'll press the Enter key or the Return key on the Mac to accept that change. And then I'll switch back to the black arrow selection tool up here at the top of the tool box. And finally, I'll go up to the Select menu and choose Deselect in order to entirely deselect my artwork. And that is how you create and modify a radial gradient here inside Illustrator.`
        },
        {
          role: "assistant", content: `How to Create and Modify a Radial Gradient in Illustrator:
          1. Open Adobe Illustrator and create a new document.
          2. Draw a circle using the black arrow tool.
          3. Switch to the Gradient Tool, which looks like a little gradient, and click inside the circle to apply the last applied gradient, which happens to be a three-color linear gradient.
          4. Double-click on the first color stop, located on the left-hand side, and change its color to a very dark shade of blue that begins with R=27.
          5. Grab the second color stop and get rid of it by dragging it down off of the gradient annotator.
          6. Double-click on the last color stop, located on the right-hand side, and change its color to white.
          7. Switch the style of gradient from linear to radial by going to the Properties panel and clicking on the radial gradient option.
          8. Click on the dot dot dot icon located in the bottom right corner of the gradient area and click on the Reverse Gradient icon to swap the colors, making the gradient go from white on the inside to dark blue on the outside.
          9. To change the center of the gradient relative to the outside edges, drag the tiny black circle with the black arrowhead up and out.
          10. To constrain the angle of the gradient to 45 degrees, move your cursor slightly beyond the square around the outside edge of
          the circle, and press and hold the Shift key as you drag.
          11. To add a dark edge, press and hold the Alt key (Option key on Mac) and duplicate an existing color stop by dragging it.
          12. Double-click on the duplicated color stop to bring up the swatches and change its color to black.
          13. Change the location value to 93% by pressing the Enter key (Return key on Mac).
          14. Press Alt (Option key on Mac) again and drag the blue color stop along the outside edge inward to make another copy of it.
          15. Double-click on the new blue color stop and change the location value to 86%, then press Enter (Return key on Mac).
          16. If necessary, adjust the colors by selecting the color stop and changing its color in the Fill option located in the Appearance section of the Properties panel.
          17. Switch back to the black arrow selection tool and go to the Select menu, and choose Deselect to entirely deselect your artwork.
          Congratulations, you have successfully created and modified a radial gradient in Adobe Illustrator.' `
        },
        {
          role: "user", content: "Turn the following video transcript into a step-by-step written tutorial (numbered) while explaining each step: " + tutorial
        },
      ],
    })

    const stepByStepTutorial = tutorialCompletion.data.choices[0].message.content

    // now we are going to match the right keywords used by the speaker to the right steps
    let response = await bingAIClient.sendMessage(`I'll give a step-by-step tutorial and a speech and you have to place the EXACT SHORT GROUP OF WORDS USED IN THE SPEECH wrapped inside brackets after each step after which it is appropriate to take screenshots. This the step-by-step tutorial: ${stepByStepTutorial}. And this is the speech: ${tutorial}`, {
      // (Optional) Set a conversation style for this message (default: 'balanced')
      toneStyle: 'precise', // or creative, precise, fast
    });

    const keyPhrases = response.response.match(/(?<=\[).*?(?=\])/g);

    function insertImages(imageDescriptions, tutorialText) {
        const stepRegex = /(\d+\. .+?)(?=\d+\. |$)/gs
        const steps = tutorialText.match(stepRegex);

        const tutorialWithImages = steps.map((step, index) => {
          const imageTag = (index === 0 || index === steps.length) ? '' : `<img src='${imageDescriptions[index - 1]}' alt='' />`;
          return imageTag + step;
        });

        tutorialWithImages.push(`<img src='${imageDescriptions[imageDescriptions.length - 1]}' alt='' />`);

        return tutorialWithImages.join('');
    }

    const tutorialWithImgs = insertImages(keyPhrases, stepByStepTutorial)


    // this is for the tutorials
    const htmlCompletion = await openai.createChatCompletion({
        model: "gpt-3.5-turbo",
        messages: [
          {
            role: "system", content: "You are a helpful assistant that converts a step-by-step written tutorial to an appropriate HTML format."
          },
          {
            role: "user", content: `Convert the following step-by-step tutorial to an appropriate HTML format: 1. Open Adobe Illustrator and create a new document.<img src='Instructor' alt='' />2. Draw a circle using the black arrow tool.<img src='select that circle with the black arrow tool' alt='' />3. Switch to the Gradient Tool, which looks like a little gradient, and click inside the circle to apply the last applied gradient, which happens to be a three-color linear gradient.<img src='switch to the Gradient Tool' alt='' />4. Double-click on the first color stop, located on the left-hand side, and change its color to a very dark shade of blue that begins with R=27.<img src='double-click on that first color stop' alt='' />5. Grab the second color stop and get rid of it by dragging it down off of the gradient annotator.<img src='get rid of it by dragging it down off of the gradient annotator' alt='' />6. Double-click on the last color stop, located on the right-hand side, and change its color to white.<img src='double-click on the last color stop' alt='' />7. Switch the style of gradient from linear to radial by going to the Properties panel and clicking on the radial gradient option.<img src='click on radial' alt='' />8. Click on the dot dot dot icon located in the bottom right corner of the gradient area and click on the Reverse Gradient icon to swap the colors, making the gradient go from white on the inside to dark blue on the outside.<img src='click on this icon right here Reverse Gradient' alt='' />9. To change the center of the gradient relative to the outside edges, drag the tiny black circle with the black arrowhead up and out.<img src='drag this little tiny black circle' alt='' />10. To constrain the angle of the gradient to 45 degrees, move your cursor slightly beyond the square around the outside edge ofthe circle, and press and hold the Shift key as you drag.<img src='press hold Shift key drag' alt='' />11. To add a dark edge, press and hold the Alt key (Option key on Mac) and duplicate an existing color stop by dragging it.<img src='duplicate existing color stop' alt='' />12. Double-click on the duplicated color stop to bring up the swatches and change its color to black.<img src='change its color black' alt='' />13. Change the location value to 93% by pressing the Enter key (Return key on Mac).<img src='location value 93%' alt='' />14. Press Alt (Option key on Mac) again and drag the blue color stop along the outside edge inward to make another copy of it.<img src='make yet another copy' alt='' />15. Double-click on the new blue color stop and change the location value to 86%, then press Enter (Return key on Mac).<img src='location value 86%' alt='' />16. If necessary, adjust the colors by selecting the color stop and changing its color in the Fill option located in the Appearance section of the Properties panel.<img src='change that color Fill option here inside Appearance section Properties panel' alt='' />17. Switch back to the black arrow selection tool and go to the Select menu, and choose Deselect to entirely deselect your artwork.Congratulations, you have successfully created and modified a radial gradient in Adobe Illustrator.<img src='choose Deselect' alt='' />`
          },
          {
            role: "assistant", content: `<div>
            <div>
              <h3>1. Open Adobe Illustrator and create a new document.<h3>
              <img src='Instructor' alt='' />
            </div>
            <div>
              <h3>2. Draw a circle using the Black Arrow tool.<h3>
              <img src='select that circle with the black arrow tool' alt='' />
            </div>
            <div>
              <h3>3. Switch to the Gradient Tool, which looks like a little gradient, and click inside the circle to apply the last applied gradient, which happens to be a three-color linear gradient.<h3>
              <img src='switch to the Gradient Tool' alt='' />
            </div>
            <div>
              <h3>4. Double-click on the first color stop, located on the left-hand side, and change its color to a very dark shade of blue that begins with R=27.<h3>
              <img src='double-click on that first color stop' alt='' />
            </div>
            <div>
              <h3>5. Grab the second color stop and get rid of it by dragging it down off of the gradient annotator.<h3>
              <img src='get rid of it by dragging it down off of the gradient annotator' alt='' />
            </div>
            <div>
              <h3>6. Double-click on the last color stop, located on the right-hand side, and change its color to white.<h3>
              <img src='double-click on the last color stop' alt='' />
            </div>
            <div>
              <h3>7. Switch the style of gradient from linear to radial by going to the Properties panel and clicking on the radial gradient option.<h3>
              <img src='click on radial' alt='' />
            </div>
            <div>
              <h3>8. Click on the dot dot dot icon located in the bottom right corner of the gradient area and click on the Reverse Gradient icon to swap the colors, making the gradient go from white on the inside to dark blue on the outside.<h3>
              <img src='click on this icon right here Reverse Gradient' alt='' />
            </div>
            <div>
              <h3>9. To change the center of the gradient relative to the outside edges, drag the tiny black circle with the black arrowhead up and out.<h3>
              <img src='drag this little tiny black circle' alt='' />
            </div>
            <div>
              <h3>10. To constrain the angle of the gradient to 45 degrees, move your cursor slightly beyond the square around the outside edge of\nthe circle, and press and hold the Shift key as you drag.<h3>
              <img src='press hold Shift key drag' alt='' />
            </div>
            <div>
              <h3>11. To add a dark edge, press and hold the Alt key (Option key on Mac) and duplicate an existing color stop by dragging it.<h3>
              <img src='duplicate existing color stop' alt='' />
            </div>
            <div>
              <h3>12. Double-click on the duplicated color stop to bring up the swatches and change its color to black.<h3>
              <img src='change its color black' alt='' />
            </div>
            <div>
              <h3>13. Change the location value to 93% by pressing the Enter key (Return key on Mac).<h3>
              <img src='location value 93%' alt='' />
            </div>
            <div>
              <h3>14. Press Alt (Option key on Mac) again and drag the blue color stop along the outside edge inward to make another copy of it.<h3>
              <img src='make yet another copy' alt='' />
            </div>
            <div>
              <h3>15. Double-click on the new blue color stop and change the location value to 86%, then press Enter (Return key on Mac).<h3>
              <img src='location value 86%' alt='' />
            </div>
            <div>
              <h3>16. If necessary, adjust the colors by selecting the color stop and changing its color in the Fill option located in the Appearance section of the Properties panel.<h3>
              <img src='change that color Fill option here inside Appearance section Properties panel' alt='' />
            </div>
            <div>
              <h3>17. Double-click on the new blue color stop and change the location value to 86%, then press Enter (Return key on Mac).<h3>
              <img src='choose Deselect' alt='' />
            </div>
           </div>
           `
          },
          {
            role: "user", content: `Convert the following step-by-step tutorial to an appropriate HTML format: ` + tutorialWithImgs
          },
        ],
    })

    const finalTutorialWithImages = htmlCompletion.data.choices[0].message.content
    const lecWithImgs = `<h1>${videoTitle}</h1>\n` + finalTutorialWithImages

    return { lecWithImgs, keyPhrases }

  }

}





app.listen(4050, function() {
  console.log('Server listening on port 4050...')
})
