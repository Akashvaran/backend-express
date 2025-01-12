import jwt from 'jsonwebtoken';

export const protectRoutes = async (req, res, next) => {
  let token;
  if (req.cookies && req.cookies.jwt) {
    token = req.cookies.jwt;

    try {
      const decodedData = jwt.verify(token, process.env.JWT_SECRET);
      req.user = decodedData;
      return next();
    } catch (err) {
      return res.status(401).json({
        message: "Invalid token or Token was expired",
      });
    }
  }

  if (!token) {
    return res.status(401).json({
      status: false,
      message: "Not authorized, token not available",
    });
  }
};

export const authoriseRoute = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        message: "You don't have access to this task",
      });
    }
    next();
  };
};
