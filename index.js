const express = require('express');
const app = express();
const { User } = require("./models");
const passport = require('passport');  // authentication
const connectEnsureLogin = require('connect-ensure-login'); //authorization
const session = require('express-session');  // session middleware for cookie support
const { randomBytes } = require('crypto'); // Nodejs Build-in library

function generateToken() {
    return new Promise((resolve, reject) => {
        randomBytes(20, (err, buf) => {
            if (err) {
                reject(err);
            } else {
                resolve(buf.toString('hex'));
            }
        });
    });
}

const passwordResetTokens = {};
const LocalStrategy = require('passport-local').Strategy

// Middleware to parse JSON bodies && Sessions storage
app.use(express.json());
app.use(session({
  secret: 'my-super-secret-key-7218728182782818218782718hsjahsu8as8a8su88',
  resave: false,
  saveUninitialized: true,
  cookie: { maxAge: 24* 60 * 60 * 1000 } // 24 hour
}));
app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy(
  {
    usernameField: 'email',
    passwordField: 'password'
  },
  function(username, password, done) {
    User.findOne({ where: { email: username, password: password } }).then(function(user) {
      return done(null, user);
    }).catch((error) => {
      return done(error);
    });
  }
));

passport.serializeUser(function(user, done) {
  console.log("Serializing user in session: ", user.id)
  done(null, user.id); 
});
passport.deserializeUser(function(id, done) {
  User.findByPk(id)
    .then((user) => {
      done(null, user);
    })
    .catch((error) => {
      done(error, null);
    });
});

// if person is not login show this route
app.get('/', function (request, response) {
    response.send('Hello Guest You are Not logined! Please login OR Signup');   
});

// if person is logged in show this route
app.get('/page', connectEnsureLogin.ensureLoggedIn(), async function (request, response) {
  const currentUser = request.user;
  if (currentUser) {
      response.send(`Hi ${currentUser.UserName}, welcome to the page!`);
  } else {
      // If the user is not logged in for some reason 
      response.send('Hi there, you are not logged in for some reason!');
  }
});

// 1.1 User Registration using Email Password and username API 
app.post('/users', async function (request, response) {
    try {
        const user = await User.create({ 
            UserName: request.body.UserName,
            email: request.body.email, 
            password: request.body.password 
        });
        request.login(user, function(err) {
          if (err) {
            console.log(err);
          }
          return response.redirect('/page');
        });
        //response.redirect("/page"); // Redirected to root path
    } catch (error) {
        console.error(error);
        response.status(500).send("Error creating user");
    }
});

// 1.2 User Login using username and password
app.get('/login', function(request, response) {
  response.send("you need to use post method of login to login")
});
app.post('/login', passport.authenticate('local'),  function(request, response) {
  console.log(request.user)
	response.redirect('/page');
});

app.get('/signout', function(request, response, next) {
  request.logout(function(err) {
    if (err) { return next(err); }
    response.redirect('/');
  });
});
app.post('/change-password', connectEnsureLogin.ensureLoggedIn(), async function (request, response) {
  try {
      const currentUser = request.user;
      const newPassword = request.body.newPassword;

      // *** Never Ever Try to response.send Twice *** 
      if (!newPassword) {
          return response.status(400).send("New password is required");
      }
      currentUser.password = newPassword;
      await currentUser.save();
      response.redirect('/');
  } catch (error) {
      console.error(error);
      response.status(500).send("Error changing password");
  }
});

// 1.3 Forget User password API
// part 1 genrate token/otp
app.post('/forgot-password', async function (request, response) {
  try {
      const userEmail = request.body.email;
      const user = await User.findOne({ where: { email: userEmail } });
      if (!user) {
          return response.status(404).send("User not found");
      }
      const token = await generateToken();
      passwordResetTokens[user.email] = token;

      // Send the password reset email with a link containing the token
      // You can use a library like nodemailer to send emails
      // Example: sendPasswordResetEmail(user.email, token);

      // For demonstration purposes, let's just log the token
      console.log("Password reset token:", token);
      response.send("Password reset instructions sent to your email");
  } catch (error) {
      console.error(error);
      response.status(500).send("Error resetting password");
  }
});

// 2nd part POST endpoint for handling password reset confirmation
app.post('/reset-password', async function (request, response) {
  try {
      const userEmail = request.body.email;
      const token = request.body.token;
      const newPassword = request.body.newPassword;
      if (passwordResetTokens[userEmail] !== token) {
          return response.status(400).send("Invalid or expired token");
      }
      const user = await User.findOne({ where: { email: userEmail } });
      if (!user) {
          return response.status(404).send("User not found");
      }
      user.password = newPassword;
      await user.save();
      delete passwordResetTokens[userEmail];
      response.send("Password reset successfully");
  } catch (error) {
      console.error(error);
      response.status(500).send("Error resetting password");
  }
});

app.listen(3000, () => {
    console.log("listening on port 3000");
});
