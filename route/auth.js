const express = require("express");
const auth = require('../middleware/auth');
const {
    postLogin,
    decodeToken,
} = require("../controllers/authController.js");
const authRouter = express.Router();

authRouter.post('/login', /* middleware */ postLogin);                      // login, refresh token 재발급
authRouter.post('/get/decoded/token', auth.isAuthenticated, decodeToken);   // access token decoded data return
authRouter.post('/temp/get/decoded/token', auth.decodeTokenChk);            // access & refresh token decoded data check
authRouter.post('/get/new/access/token', auth.getNewAccessToken);           // access token 재발급, refresh token 만료 에러 response 
authRouter.post('/get/new/refresh/token', auth.getRefreshToken);         // refresh token 재발급, refresh token 만료 에러 response 

module.exports = authRouter;
