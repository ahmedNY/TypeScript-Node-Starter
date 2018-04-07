import passport from "passport";
import request from "request";
import passportLocal from "passport-local";
import passportFacebook from "passport-facebook";
import _ from "lodash";

// import { User, UserType } from '../models/User';
import { UmUser } from "../models/User";
import { getManager } from "typeorm";
import { Request, Response, NextFunction } from "express";

const LocalStrategy = passportLocal.Strategy;
const FacebookStrategy = passportFacebook.Strategy;

passport.serializeUser<any, any>((user, done) => {
  done(undefined, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const userRepository = getManager().getRepository(UmUser);
    const user = await userRepository.findOneById(id);
    done(false, user);
  } catch (err) {
    done(err);
  }
});


/**
 * Sign in using Email and Password.
 */
passport.use(new LocalStrategy({ usernameField: "email" }, async (email, password, done) => {
  try {
    const userRepository = getManager().getRepository(UmUser);
    const user = await userRepository.findOne({email: email.toLocaleLowerCase()});
    if (!user) {
      return done(undefined, false, { message: `Email ${email} not found.` });
    }
    user.comparePassword(password, (err: Error, isMatch: boolean) => {
      if (err) { return done(err); }
      if (isMatch) {
        return done(undefined, user);
      }
      return done(undefined, false, { message: "Invalid email or password." });
    });
  } catch (error) {
    return done(error);
  }
}));


/**
 * OAuth Strategy Overview
 *
 * - User is already logged in.
 *   - Check if there is an existing account with a provider id.
 *     - If there is, return an error message. (Account merging not supported)
 *     - Else link new OAuth account with currently logged-in user.
 * - User is not logged in.
 *   - Check if it's a returning user.
 *     - If returning user, sign in and we are done.
 *     - Else check if there is an existing account with user's email.
 *       - If there is, return an error message.
 *       - Else create a new account.
 */


/**
 * Sign in with Facebook.
 */
passport.use(new FacebookStrategy({
  clientID: process.env.FACEBOOK_ID,
  clientSecret: process.env.FACEBOOK_SECRET,
  callbackURL: "/auth/facebook/callback",
  profileFields: ["name", "email", "link", "locale", "timezone"],
  passReqToCallback: true
}, async (req: any, accessToken, refreshToken, profile, done) => {
  if (req.user) {
    const userRepository = getManager().getRepository(UmUser);
    try {
      const existingUser = await userRepository.findOne();
      if (existingUser) {
        req.flash("errors", { msg: "There is already a Facebook account that belongs to you. Sign in with that account or delete it, then link it with your current account." });
        done(undefined);
      } else {
        const user = await userRepository.findOneById(req.user.id);
        user.facebook = profile.id;
        user.facebookToken = accessToken;
        user.name = user.name || `${profile.name.givenName} ${profile.name.familyName}`;
        user.gender = user.gender || profile._json.gender;
        user.picture = user.picture || `https://graph.facebook.com/${profile.id}/picture?type=large`;
        await userRepository.save(user);
        req.flash("info", { msg: "Facebook account has been linked." });
        done(undefined, user);
      }
    } catch (error) {
      return done(error);
    }
  } else {
    try {
      const userRepository = getManager().getRepository(UmUser);
      const existingUser = await userRepository.findOne();
      if (existingUser) {
        return done(undefined, existingUser);
      }
      const existingEmailUser = await userRepository.findOne({ email: profile._json.email});
      if (existingEmailUser) {
        req.flash("errors", { msg: "There is already an account using this email address. Sign in to that account and link it with Facebook manually from Account Settings." });
        done(undefined);
      } else {
        const user: UmUser = userRepository.create();
        user.email = profile._json.email;
        user.facebook = profile.id;
        user.facebookToken = accessToken;
        user.name = `${profile.name.givenName} ${profile.name.familyName}`;
        user.gender = profile._json.gender;
        user.picture = `https://graph.facebook.com/${profile.id}/picture?type=large`;
        user.location = (profile._json.location) ? profile._json.location.name : "";
        await userRepository.save(user);
        done(undefined, user);
      }
    } catch (error) {
      if (error) { return done(error); }
    }
  }
}));

/**
 * Login Required middleware.
 */
export let isAuthenticated = (req: Request, res: Response, next: NextFunction) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/login");
};

/**
 * Authorization Required middleware.
 */
export let isAuthorized = (req: Request, res: Response, next: NextFunction) => {
  const provider = req.path.split("/").slice(-1)[0];

  if (_.find(req.user.tokens, { kind: provider })) {
    next();
  } else {
    res.redirect(`/auth/${provider}`);
  }
};
