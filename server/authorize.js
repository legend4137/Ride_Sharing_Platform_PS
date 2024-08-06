const jwt = require('jsonwebtoken');
require('dotenv').config();

const jwtSecret = process.env.JWT_SECRET;

module.exports = (roles) => {
  return (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(403).send('No token provided');

    jwt.verify(token, jwtSecret, (err, decoded) => {
      if (err) return res.status(403).send('Invalid token');
      if (!roles.includes(decoded.role)) return res.status(403).send('Access denied');
      req.user = {
        userId: decoded.userId,
        role: decoded.role,
        username: decoded.username // Add username from the token
      };
      next();
    });
  };
};
