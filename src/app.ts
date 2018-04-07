import express from "express";
import compression from "compression";  // compresses requests
import session from "express-session";
import mysqlSession from "express-mysql-session";
import bodyParser from "body-parser";
import logger from "./util/logger";
import lusca from "lusca";
import dotenv from "dotenv";
import flash from "express-flash";
import path from "path";
import passport from "passport";
import expressValidator from "express-validator";
import bluebird from "bluebird";
import { SESSION_SECRET } from "./util/secrets";

const MySQLStore = mysqlSession(session);
// typeorm
import "reflect-metadata";
import { createConnection } from "typeorm";

// create connection with database
// note that it's not active database connection
// TypeORM creates connection pools and uses them for your requests
createConnection(
  {
    "type": "mysql",
    "host": "localhost",
    "port": 3306,
    "username": "root",
    "password": "123",
    "database": "express-fuel-delivery",
    "synchronize": true,
    "entities": [
      "dist/models/*.js"
    ],
    "subscribers": [
      "dist/subscriber/*.js"
    ],
    "migrations": [
      "dist/migration/*.js"
    ],
    "cli": {
      "entitiesDir": "src/models",
      "migrationsDir": "src/migration",
      "subscribersDir": "src/subscriber"
    }
  }
).then(function () {
  console.log("Connection created successfully");
}).catch(error => console.log("TypeORM connection error: ", error));

// Load environment variables from .env file, where API keys and passwords are configured
dotenv.config({ path: ".env.example" });

// Controllers (route handlers)
import * as homeController from "./controllers/home";
import * as userController from "./controllers/user";
import * as apiController from "./controllers/api";
import * as contactController from "./controllers/contact";
import * as postController from "./controllers/post";


// API keys and Passport configuration
import * as passportConfig from "./config/passport";

// Create Express server
const app = express();


// Express configuration
app.set("port", process.env.PORT || 3000);
app.set("views", path.join(__dirname, "../views"));
app.set("view engine", "pug");
app.use(compression());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(expressValidator());

// setup express session
const options = {
  host: "localhost",
  port: 3306,
  user: "root",
  password: "123",
  database: "express-fuel-delivery"
};
const sessionStore = new MySQLStore(options);
app.use(session({
  resave: true,
  saveUninitialized: false,
  secret: SESSION_SECRET,
  // store: new MongoStore({
  //   url: mongoUrl,
  //   autoReconnect: true
  // })
  store: sessionStore
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());
app.use(lusca.xframe("SAMEORIGIN"));
app.use(lusca.xssProtection(true));
app.use((req, res, next) => {
  res.locals.user = req.user;
  next();
});
app.use((req, res, next) => {
  // After successful login, redirect back to the intended page
  if (!req.user &&
    req.path !== "/login" &&
    req.path !== "/signup" &&
    !req.path.match(/^\/auth/) &&
    !req.path.match(/\./)) {
    req.session.returnTo = req.path;
  } else if (req.user &&
    req.path == "/account") {
    req.session.returnTo = req.path;
  }
  next();
});

app.use(
  express.static(path.join(__dirname, "public"), { maxAge: 31557600000 })
);

/**
 * Primary app routes.
 */
app.get("/", homeController.index);
app.get("/login", userController.getLogin);
app.post("/login", userController.postLogin);
app.get("/logout", userController.logout);
app.get("/forgot", userController.getForgot);
app.post("/forgot", userController.postForgot);
app.get("/reset/:token", userController.getReset);
app.post("/reset/:token", userController.postReset);
app.get("/signup", userController.getSignup);
app.post("/signup", userController.postSignup);
app.get("/contact", contactController.getContact);
app.post("/contact", contactController.postContact);
app.get("/account", passportConfig.isAuthenticated, userController.getAccount);
app.post("/account/profile", passportConfig.isAuthenticated, userController.postUpdateProfile);
app.post("/account/password", passportConfig.isAuthenticated, userController.postUpdatePassword);
app.post("/account/delete", passportConfig.isAuthenticated, userController.postDeleteAccount);
app.get("/account/unlink/:provider", passportConfig.isAuthenticated, userController.getOauthUnlink);
app.get("/posts", postController.postGetAllAction);
app.get("/posts/:id", postController.postGetByIdAction);
app.post("/posts", passportConfig.jwtRoute, postController.postSaveAction);
app.post("/profile", passport.authenticate("jwt", { session: false }),
    function(req, res) {
        res.send(req.user);
    }
);

/**
 * API examples routes.
 */
app.get("/api", apiController.getApi);
app.get("/api/facebook", passportConfig.isAuthenticated, passportConfig.isAuthorized, apiController.getFacebook);

/**
 * OAuth authentication routes. (Sign in)
 */
app.get("/auth/facebook", passport.authenticate("facebook", { scope: ["email", "public_profile"] }));
app.get("/auth/facebook/callback", passport.authenticate("facebook", { failureRedirect: "/login" }), (req, res) => {
  res.redirect(req.session.returnTo || "/");
});

export default app;