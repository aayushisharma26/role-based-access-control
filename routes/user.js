import express from 'express';
import jwt from 'jsonwebtoken';

const router = express.Router();

const authenticate = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Authentication required' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

const authorize = (roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    next();
  };
};

router.get('/profile', authenticate, (req, res) => {
  res.json({ message: 'Profile accessed', userId: req.user.userId, role: req.user.role });
});

router.get('/admin', authenticate, authorize(['admin']), (req, res) => {
  res.json({ message: 'Admin page accessed' });
});

router.get('/moderator', authenticate, authorize(['admin', 'moderator']), (req, res) => {
  res.json({ message: 'Moderator page accessed' });
});

export default router;

