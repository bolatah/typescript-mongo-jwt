import { Request, Response, NextFunction } from "express";
import logging from "../config/logging";
import jwt from "jsonwebtoken";
import config from "../config/config";

const NAMESPACE = "Auth";

const extractJWT = (req: Request, res: Response, next: NextFunction) => {
  logging.info(NAMESPACE, "Validating JWT token");

  let token = req.headers.authorization?.split(" ")[1];

  if (token) {
    jwt.verify(token, config.server.token.secret, (error, decoded) => {
      if (error) {
        res.status(404).send({
          message: error.message,
          error,
        });
      } else {
        res.locals.jwt = decoded;
        next();
      }
    });
  } else {
    return res.status(401).send({
      message: "No token provided",
    });
  }
};
export default extractJWT;
