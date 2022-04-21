import { Request, Response, NextFunction } from "express";
import mongoose from "mongoose";
import bcryptjs from "bcryptjs";

import logging from "../config/logging";
import User from "../models/user";
import signJWT from "../functions/signJWT";

const NAMESPACE = "Users";

const validateToken = (req: Request, res: Response, next: NextFunction) => {
  logging.info(NAMESPACE, "Token validation, user authorized");
  return res.status(200).json({
    message: "User authorized",
  });
};

const register = (req: Request, res: Response, next: NextFunction) => {
  let { username, password } = req.body;
  bcryptjs.hash(password, 10, (hashError, hash) => {
    if (hashError) {
      logging.error(NAMESPACE, hashError.message, hashError);
      return res.status(500).json({
        message: hashError.message,
        error: hashError,
      });
    }
    const _user = new User({
      _id: new mongoose.Types.ObjectId(),
      username,
      password: hash,
    });
    return _user
      .save()
      .then((user) => {
        logging.info(NAMESPACE, "User registered");
        return res.status(201).json({
          message: "User registered",
          user,
        });
      })
      .catch((error) => {
        logging.error(NAMESPACE, error.message, error);
        return res.status(500).json({
          message: error.message,
          error,
        });
      });
  });
};

const login = (req: Request, res: Response, next: NextFunction) => {
  let { username, password } = req.body;
  User.findOne({ username })
    .then((user) => {
      if (!user) {
        logging.error(NAMESPACE, "User not found");
        return res.status(401).json({
          message: "User not found",
        });
      }
      bcryptjs.compare(password, user.password, (error, result) => {
        if (error) {
          logging.error(NAMESPACE, error.message, error);
          return res.status(404).json({
            message: "User not found",
          });
        } else if (result) {
          logging.info(NAMESPACE, "User logged in");
          signJWT(user, (error, token) => {
            if (error) {
              logging.error(NAMESPACE, error.message, error);
              return res.status(401).json({
                message: "Unauthorized",
                error,
              });
            } else if (token) {
              return res.status(200).json({
                message: "Auth successful",
                token,
                _id: user._id,
                username: user.username,
              });
            }
          });
        }
      });
    })
    .catch((error) => {
      logging.error(NAMESPACE, error.message, error);
      return res.status(500).json({
        message: error.message,
        error,
      });
    });
};

const getAllUsers = (req: Request, res: Response, next: NextFunction) => {
  User.find()
    .select("-password")
    // the above select method is for not returning the password for the security reasons
    .exec()
    .then((users) => {
      logging.info(NAMESPACE, "Users found");
      return res.status(200).json({
        count: users.length,
        users,
      });
    })
    .catch((error) => {
      logging.error(NAMESPACE, error.message, error);
      return res.status(500).json({
        message: error.message,
        error,
      });
    });
};

export default { validateToken, register, login, getAllUsers };
