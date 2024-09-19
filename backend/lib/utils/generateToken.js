import jwt from "jsonwebtoken";

/**
 * Generates a JWT token for the given user ID and sets it as a secure cookie in the response.
 *
 * @param {string} userId - The ID of the user to generate the token for
 * @param {object} res - The HTTP response object to set the cookie on
 * @return {void}
 */
export const generateTokenAndSetCookie = (userId, res) => {
  // to generate the token => JWT_SECRET openssl rand -base64 32
  const token = jwt.sign({ userId }, process.env.JWT_SECRET, {
    expiresIn: "15d",
  });

  res.cookie("jwt", token, {
    maxAge: 15 * 24 * 60 * 60 * 1000, //MS
    httpOnly: true, // prevent XSS attacks cross-site scripting attacks
    sameSite: "strict", // CSRF attacks cross-site request forgery attacks
    secure: process.env.NODE_ENV !== "development",
  });
};
