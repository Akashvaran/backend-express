import express from 'express';
import { signup, login, Verify, logout, forgetPassword, resetPassword } from '../userControllers/authController.js';
import { protectRoutes } from '../utils/roleVerification.js';

const authRouter = express.Router();

authRouter.post('/signup', signup);
authRouter.post('/login', login);
authRouter.get('/verify', Verify);
authRouter.post('/logout', protectRoutes, logout);
authRouter.post('/forget',forgetPassword)
authRouter.put('/reset:token',resetPassword)

export { authRouter };
