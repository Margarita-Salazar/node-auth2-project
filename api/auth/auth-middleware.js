const { JWT_SECRET } = require("../secrets"); // use this secret!

const jwt = require("jsonwebtoken");

const Users = require('../users/users-model')

const bcrypt = require('bcryptjs')

const restricted = (req, res, next) => {
  const token = req.headers.authorization;
  if (token) {
    jwt.verify(token, JWT_SECRET, (err, decode) => {
      if (err) {
        next({
          status: 401,
          message: "Token invalid",
        });
      } else {
        req.decodeJwt = decode;
        next();
      }
    });
  } else {
    next({
      status: 401,
      message: "Token required",
    });
  }
};

const only = (role_name) => (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */
 if(req.decodeJwt.role_name === role_name){
   next()
 } else {
    next({
      status: 403,
      message: 'This is not for you'
    })
 }
 
};

const checkUsernameExists = (req, res, next) => {
  /*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */
    const { username, password } = req.body

    Users.findBy({ username })
    .then(([user]) => {
      if(user && bcrypt.compareSync(password, user.password)) {
        next()
      } else {
        next({
          status: 401,
          message: 'Invalid credentials'
        })
      }
    })
    .catch(next);
};

const validateRoleName = (req, res, next) => {
  /*
    If the role_name in the body is valid, set req.role_name to be the trimmed string and proceed.

    If role_name is missing from req.body, or if after trimming it is just an empty string,
    set req.role_name to be 'student' and allow the request to proceed.

    If role_name is 'admin' after trimming the string:
    status 422
    {
      "message": "Role name can not be admin"
    }

    If role_name is over 32 characters after trimming the string:
    status 422
    {
      "message": "Role name can not be longer than 32 chars"
    }
  */
  const { role_name } = req.body

  if(
    role_name ||
    role_name.trim()) {
      req.role_name = role_name.trim()

      if(req.role_name.length > 32){
        next({
          status: 422,
          message: 'role name can not be longer than 32 chars'
        })
      }else if(req.role_name === 'admin'){
        next({
          status: 422,
          message: 'Role name can not be admin'
        })
      }else{
        next()
      }
  }else {
    req.role_name = 'student'
    next()
  }
};

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
};
