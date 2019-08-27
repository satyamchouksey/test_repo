const jwt = require('jsonwebtoken');
const config = require('config');
//middleware has access to 3 object req,res,next(callback we have to run so it moves to next middleware)
module.exports = function(req, res, next) {
  // Get token from header(req)
  const token = req.header('x-auth-token');

  // Check if not token
  if (!token) {
    return res.status(401).json({ msg: 'No token, authorization denied' });
  }

  // Verify token
  try {
    //verify token from req header using secret key
    const decoded = jwt.verify(token, config.get('jwtSecret'));
    //put decoded payload in user
    req.user = decoded.user;
    next();
  } catch (err) {
    res.status(401).json({ msg: 'Token is not valid' });
  }
};
