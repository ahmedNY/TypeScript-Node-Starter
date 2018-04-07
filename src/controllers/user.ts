import async from "async";
import crypto from "crypto";
import nodemailer from "nodemailer";
import passport from "passport";
import { UmUser } from "../models/User";
import { getManager } from "typeorm";
import { Request, Response, NextFunction } from "express";
import { IVerifyOptions } from "passport-local";
const request = require("express-validator");

import JWT from "jsonwebtoken";
import { JWT_SECRET } from "../util/secrets";


function createJwtToken(user: UmUser) {
  return "Bearer " + JWT.sign({
    data: user.id
  }, "secret", { expiresIn: "15 days" });
}

/**
 * GET /login
 * Login page.
 */
export let getLogin = (req: Request, res: Response) => {
  if (req.user) {
    return res.redirect("/");
  }
  res.render("account/login", {
  title: "Login"
  });
};

/**
 * POST /login
 * Sign in using email and password.
 */
export let postLogin = (req: Request, res: Response, next: NextFunction) => {
  req.assert("email", "Email is not valid").isEmail();
  req.assert("password", "Password cannot be blank").notEmpty();
  req.sanitize("email").normalizeEmail({ gmail_remove_dots: false });

  const errors = req.validationErrors();

  if (errors) {
    req.flash("errors", errors);
    return res.redirect("/login");
  }

  /*
  passport.authenticate("local", (err: Error, user: UmUser, info: IVerifyOptions) => {
    if (err) { return next(err); }
    if (!user) {
      req.flash("errors", info.message);
      return res.redirect("/login");
    }
    req.logIn(user, (err) => {
      if (err) { return next(err); }
      req.flash("success", { msg: "Success! You are logged in." });
      res.redirect(req.session.returnTo || "/");
    });
  })(req, res, next);
  */


 passport.authenticate("local", (err: Error, user: UmUser, info: IVerifyOptions) => {
  if (err) { return next(err); }
  if (!user) {
    return res.status(401).json({
      message: "User not found"
    });
  }

  const token = createJwtToken(user);
  return res.json({
    token
  });
})(req, res, next);

};

/**
 * GET /logout
 * Log out.
 */
export let logout = (req: Request, res: Response) => {
  req.logout();
  res.redirect("/");
};

/**
 * GET /signup
 * Signup page.
 */
export let getSignup = (req: Request, res: Response) => {
  if (req.user) {
    return res.redirect("/");
  }
  res.render("account/signup", {
    title: "Create Account"
  });
};

/**
 * POST /signup
 * Create a new local account.
 */
export let postSignup = async (req: Request, res: Response, next: NextFunction) => {
  req.assert("email", "Email is not valid").isEmail();
  req.assert("password", "Password must be at least 4 characters long").len({ min: 4 });
  req.assert("confirmPassword", "Passwords do not match").equals(req.body.password);
  req.sanitize("email").normalizeEmail({ gmail_remove_dots: false });

  const errors = req.validationErrors();

  if (errors) {
    req.flash("errors", errors);
    return res.redirect("/signup");
  }

  // load a user by a given user id
  try {
    const userRepository = getManager().getRepository(UmUser);
    const existingUser = await userRepository.findOne({ email: req.body.email });
    if (existingUser) {
      req.flash("errors", { msg: "Account with that email address already exists." });
      return res.redirect("/signup");
    }
    const user = userRepository.create({
        email: req.body.email,
        password: req.body.password
    });
    await userRepository.save(user);

    // if (req.accepts("html") === undefined) {
      const token = createJwtToken(user);
      return res.json({
        token
      });
    // }

    // req.logIn(user, (err) => {
    //   if (err) {
    //     return next(err);
    //   }
    //   res.redirect("/");
    // });
  } catch (err) {
    if (err) { return next(err); }
  }
};

/**
 * GET /account
 * Profile page.
 */
export let getAccount = (req: Request, res: Response) => {
  res.render("account/profile", {
    title: "Account Management"
  });
};

/**
 * POST /account/profile
 * Update profile information.
 */
export let postUpdateProfile = async (req: Request, res: Response, next: NextFunction) => {
  req.assert("email", "Please enter a valid email address.").isEmail();
  req.sanitize("email").normalizeEmail({ gmail_remove_dots: false });

  const errors = req.validationErrors();

  if (errors) {
    req.flash("errors", errors);
    return res.redirect("/account");
  }
  const userRepository = getManager().getRepository(UmUser);
  try {
    const user = await userRepository.findOneById(req.user.id);
    user.email = req.body.email || "";
    user.name = req.body.name || "";
    user.gender = req.body.gender || "";
    user.location = req.body.location || "";
    user.website = req.body.website || "";
    userRepository.save(user);
    req.flash("success", { msg: "Profile information has been updated." });
    res.redirect("/account");
  } catch (error) {
    if (error) { return next(error); }
  }
};

/**
 * POST /account/password
 * Update current password.
 */
export let postUpdatePassword = async (req: Request, res: Response, next: NextFunction) => {
  req.assert("password", "Password must be at least 4 characters long").len({ min: 4 });
  req.assert("confirmPassword", "Passwords do not match").equals(req.body.password);

  const errors = req.validationErrors();

  if (errors) {
    req.flash("errors", errors);
    return res.redirect("/account");
  }
  try {
    const userRepository = getManager().getRepository(UmUser);
    const user = await userRepository.findOneById(req.user.id);
    user.password = req.body.password;
    await userRepository.save(user);
    req.flash("success", { msg: "Password has been changed." });
    res.redirect("/account");
  } catch (err) {
    if (err) { return next(err); }
  }
};

/**
 * POST /account/delete
 * Delete user account.
 */
export let postDeleteAccount = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userRepository = getManager().getRepository(UmUser);
    await userRepository.removeById(req.user.id);
    req.logout();
    req.flash("info", { msg: "Your account has been deleted." });
    res.redirect("/");
  } catch (err) {
    if (err) { return next(err); }
  }
};

/**
 * GET /account/unlink/:provider
 * Unlink OAuth provider.
 */
export let getOauthUnlink = async (req: Request, res: Response, next: NextFunction) => {
  const provider = req.params.provider;

  try {
    const userRepository = getManager().getRepository(UmUser);
    const user = await userRepository.findOneById(req.user.id);
    switch (provider) {
      case "facebook":
        user.facebook = undefined;
        user.facebookToken = undefined;
        await userRepository.save(user);
        break;
        case "google":
        user.google = undefined;
      default:
        return next("unknow provider " + provider);
    }
    req.flash("info", { msg: `${provider} account has been unlinked.` });
    res.redirect("/account");
  } catch (err) {
    if (err) { return next(err); }
  }
};

/**
 * GET /reset/:token
 * Reset Password page.
 */
export let getReset = async (req: Request, res: Response, next: NextFunction) => {
  if (req.isAuthenticated()) {
    return res.redirect("/");
  }
  const userRepository = getManager().getRepository(UmUser);
  try {
    const user = await userRepository.createQueryBuilder()
                .where({ passwordResetToken: req.params.token })
                .andWhere("passwordResetExpires > :date", {date: Date.now()})
                .getOne();
    if (!user) {
      req.flash("errors", { msg: "Password reset token is invalid or has expired." });
      return res.redirect("/forgot");
    }
    res.render("account/reset", {
      title: "Password Reset"
    });
  } catch (err) {
    if (err) { return next(err); }
  }
};

/**
 * POST /reset/:token
 * Process the reset password request.
 */
export let postReset = (req: Request, res: Response, next: NextFunction) => {
  req.assert("password", "Password must be at least 4 characters long.").len({ min: 4 });
  req.assert("confirm", "Passwords must match.").equals(req.body.password);

  const errors = req.validationErrors();

  if (errors) {
    req.flash("errors", errors);
    return res.redirect("back");
  }

  async.waterfall([
    async function resetPassword(done: Function) {
      try {
        const userRepository = getManager().getRepository(UmUser);
        const user = await userRepository.createQueryBuilder()
          .where({ passwordResetToken: req.params.token })
          .andWhere("passwordResetExpires > :date", { date: Date.now() })
          .getOne();
        if (!user) {
          req.flash("errors", { msg: "Password reset token is invalid or has expired." });
          return res.redirect("back");
        }
        user.password = req.body.password;
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;
        await userRepository.save(user);
        req.logIn(user, (err) => {
          done(err, user);
        });
      } catch (err) {
        if (err) { return next(err); }
      }
    },
    function sendResetPasswordEmail(user: UmUser, done: Function) {
      const transporter = nodemailer.createTransport({
        service: "SendGrid",
        auth: {
          user: process.env.SENDGRID_USER,
          pass: process.env.SENDGRID_PASSWORD
        }
      });
      const mailOptions = {
        to: user.email,
        from: "express-ts@starter.com",
        subject: "Your password has been changed",
        text: `Hello,\n\nThis is a confirmation that the password for your account ${user.email} has just been changed.\n`
      };
      transporter.sendMail(mailOptions, (err) => {
        req.flash("success", { msg: "Success! Your password has been changed." });
        done(err);
      });
    }
  ], (err) => {
    if (err) { return next(err); }
    res.redirect("/");
  });
};

/**
 * GET /forgot
 * Forgot Password page.
 */
export let getForgot = (req: Request, res: Response) => {
  if (req.isAuthenticated()) {
    return res.redirect("/");
  }
  res.render("account/forgot", {
    title: "Forgot Password"
  });
};

/**
 * POST /forgot
 * Create a random token, then the send user an email with a reset link.
 */
export let postForgot = (req: Request, res: Response, next: NextFunction) => {
  req.assert("email", "Please enter a valid email address.").isEmail();
  req.sanitize("email").normalizeEmail({ gmail_remove_dots: false });

  const errors = req.validationErrors();

  if (errors) {
    req.flash("errors", errors);
    return res.redirect("/forgot");
  }

  async.waterfall([
    function createRandomToken(done: Function) {
      crypto.randomBytes(16, (err, buf) => {
        const token = buf.toString("hex");
        done(err, token);
      });
    },
    async function setRandomToken(token: string, done: Function) {
      try {
        const userRepository = getManager().getRepository(UmUser);
        const user = await userRepository.findOne({email: req.body.email});
        if (!user) {
          req.flash("errors", { msg: "Account with that email address does not exist." });
          return res.redirect("/forgot");
        }
        user.passwordResetToken = token;
        user.passwordResetExpires = Date.now() + 3600000; // 1 hour
      } catch (err) {
        if (err) { return done(err); }
      }
      try {
        const userRepository = getManager().getRepository(UmUser);
        const user = await userRepository.findOne({ email: req.body.email });
        if (!user) {
          req.flash("errors", { msg: "Account with that email address does not exist." });
          return res.redirect("/forgot");
        }
        user.passwordResetToken = token;
        user.passwordResetExpires = Date.now() + 3600000; // 1 hour
        await userRepository.save(user);
        done(undefined, token, user);
      } catch (err) {
        if (err) { return done(err); }
      }
    },
    function sendForgotPasswordEmail(token: string, user: UmUser, done: Function) {
      const transporter = nodemailer.createTransport({
        service: "SendGrid",
        auth: {
          user: process.env.SENDGRID_USER,
          pass: process.env.SENDGRID_PASSWORD
        }
      });
      const mailOptions = {
        to: user.email,
        from: "hackathon@starter.com",
        subject: "Reset your password on Hackathon Starter",
        text: `You are receiving this email because you (or someone else) have requested the reset of the password for your account.\n\n
          Please click on the following link, or paste this into your browser to complete the process:\n\n
          http://${req.headers.host}/reset/${token}\n\n
          If you did not request this, please ignore this email and your password will remain unchanged.\n`
      };
      transporter.sendMail(mailOptions, (err) => {
        req.flash("info", { msg: `An e-mail has been sent to ${user.email} with further instructions.` });
        done(err);
      });
    }
  ], (err) => {
    if (err) { return next(err); }
    res.redirect("/forgot");
  });
};
