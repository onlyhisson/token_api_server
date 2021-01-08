const jwt = require("jsonwebtoken");
const fs = require('fs');
const common = require("../lib/common")
const TokenGenerator = require("../lib/token-generator");
const keyData = require("../static/keys.json");
const INFO_PATH = `${__dirname}/../static/info.json`;
require('dotenv').config({path: '../.env'});

const tokenGenerator = new TokenGenerator(
    keyData.privateKey,
    keyData.publicKey,
    {
        algorithm: "HS256",
        keyid: "1",
        noTimestamp: false  // iat 는 발행시간으로 set
    }
);

/* 토큰 발급 */
const signToken = async (params, token_type) => {

    const {user_id, user_type, issuer} = params;
    const exp = getTokenExpiredDate(token_type);    // 토큰 타입에 따라 만료시간 return

    try {
        const tknInit = {   // 기본으로 들어갈 token 데이터
            audience: token_type, 
            issuer: issuer,
            jwtid: "1",     // 해당 타입 토큰 발급 횟수
            subject: "user_info" 
        };

        const tknData = {   // token에 포함되는 데이터, 비번이나 개인을 특정할 수 있는 정보는 넣지 않는다.(이메일 등)
            user_id,
            user_type,
            exp
        }

        return tokenGenerator.sign(tknData, tknInit);
    } catch(error) {
        throw error
    }
};

/* 
    토큰 인증 여부 
    - 기본적으로 권한이 있어야 할 경우에 요청되는 middleware
    - refresh token 을 access token 으로 사용 방지
*/
const isAuthenticated = async function(req, res, next) {

    const access_token = common.isNull(req.headers.authorization, null);

    if(!access_token) { // Token 이 없을 경우 
        common.errorHandler(null, res, 1000);
        return;
    }

    try {
        const decoded = await verifyAccessToken(access_token);  // 만료 체크는 제외

        const now = Math.floor((new Date).getTime());
        if(Number(now) > Number(decoded.exp)) {                 // 만료 확인
            common.errorHandler(null, res, 1003);
            return;
        }

        req.decoded = decoded;
        next()
    } catch(err) {
        if(err.message == 'invalid token') {
            common.errorHandler(null, res, 1002);
        } else if(err.local_code) {
            common.errorHandler(null, res, err.local_code);
        } else {
            common.errorHandler(null, res, 1000);
        }
    }
}

/* 
    Access Token 재발급
    - 조건 : Refresh Token 만료 전, Access Token 만료 여부 X
    - 설명 : getRefreshToken 와 다르게 isser 정보를 변경하지 않는다.(로그아웃 효과X)
*/
const getNewAccessToken = async function(req, res, next) {

    const access_token  = common.isNull(req.headers.authorization, null);
    const refresh_token = common.isNull(req.body.refresh_token, null);

    if(!access_token || !refresh_token) {
        common.errorHandler(null, res, 1000)
        return;
    }

    try {
        const at_decoded =  await verifyAccessToken(access_token);      // access token 검증 후 decode data return
        const rt_decoded =  await verifyRefreshToken(refresh_token);    // refresh token 검증 후 decode data return

        const newExp    = getTokenExpiredDate(at_decoded.aud)
        const newId     = (parseInt(at_decoded.jti) + 1).toString();
        const tknInit   = {   // 기본으로 들어갈 token 데이터
            audience: at_decoded.aud, 
            issuer: at_decoded.iss,
            jwtid: newId, 
            subject: at_decoded.sub
        };
        const tknData   = {   // token에 넣을 사용자 DB 정보 데이터 지정
            user_id : at_decoded.user_id,
            user_type : at_decoded.user_type,
            exp : newExp
        }
        const new_access_token = tokenGenerator.sign(tknData, tknInit);

        res.json({
            success_yn: true,
            new_access_token
        });
        
    } catch(err) {
        if(err.message == 'invalid token') {
            common.errorHandler(null, res, 1002);
        } else if(err.local_code) {
            common.errorHandler(null, res, err.local_code);
        } else {
            common.errorHandler(err, res, 9000);
        }
    }
}

/* 
    Access Token & Refresh Token 재발급 
    - 조건  : Refresh token 만료 전, Access Token 만료 여부 X
    - 설명  : 사용자의 로그인 정보 입력 없이 토큰 발급(로그인 요청과 차이)
              Refresh Token 만료시간 내에 로그아웃 하지 않은 경우, 사용자가 앱 최초 사용시 요청하면 계속 로그인 없이 서비스 이용 가능
*/
const getRefreshToken = async function(req, res, next) {
    const old_refresh_token  = common.isNull(req.headers.authorization, null);

    if(!old_refresh_token) {
        common.errorHandler(null, res, 1000)
        return;
    }

    try {
        const rt_decoded =  await verifyRefreshToken(old_refresh_token);    // refresh token 검증 후 decode data return

        const newIss    = await getIssuer(rt_decoded.user_id)
        const newExp    = getTokenExpiredDate(rt_decoded.aud);
        const newId     = (parseInt(rt_decoded.jti) + 1).toString();    // 해당 refresh token 로 재발급시 카운트

        const tknInit   = {   // 기본으로 들어갈 token 데이터
            audience: rt_decoded.aud, 
            issuer: newIss,
            jwtid: newId, 
            subject: rt_decoded.sub
        };
        const tknData   = {   // token에 넣을 사용자 DB 정보 데이터 지정
            user_id : rt_decoded.user_id,
            user_type : rt_decoded.user_type,
            exp : newExp
        }
        const refresh_token = tokenGenerator.sign(tknData, tknInit);

        tknInit.audience = 'access_token';
        tknInit.jwtid = "1";    // access token 은 1로 발급 횟수 초기화
        tknData.exp = getTokenExpiredDate('access_token');

        const access_token = tokenGenerator.sign(tknData, tknInit);

        // *** db 에 해당 유저의 issuer 데이터 update
        global.issuer = newIss;

        res.json({
            success_yn: true,
            access_token,
            refresh_token
        });

    } catch(err) {
        if(err.local_code) {
            common.errorHandler(null, res, err.local_code);
        } else {
            common.errorHandler(err, res, 9000);
        }
    }
};

/* token 디코드 데이터 확인 */
const decodeTokenChk = async (req, res, next) => {
    const token  = common.isNull(req.headers.authorization, null);

    if(!token) {
        common.errorHandler(null, res, 1000)
        return;
    }

    try {
        const decode = await decodeToken(token)
        res.json({
            success_yn: true,
            decode
        });
    } catch(err) {
        common.errorHandler(err, res, 9000);
    }
}

/* Access Token 검증 */
const verifyAccessToken = async (access_token) => {
    const at_decoded = await decodeToken(access_token);

    // 토큰 타입을 잘못 넣은 경우
    if(at_decoded.aud != 'access_token') throw {local_code:1002}

    // token의 issuer가 변경되면 이전 토큰은 모두 사용 불가(refresh token 재발급, 로그아웃..)
    if(at_decoded.iss != global.issuer) throw {local_code:1025}

    return at_decoded;
}

/* Refresh Token 검증 */
const verifyRefreshToken = async (refresh_token) => {
    const rt_decoded = await decodeToken(refresh_token);

    const now = Math.floor((new Date).getTime()/1000);
    const exp = Number(rt_decoded.exp);

    // 토큰 타입을 잘못 넣은 경우
    if(rt_decoded.aud != 'refresh_token') throw {local_code:1002}

    // refresh token 만료 확인
    if(now > exp) throw {local_code:1022}

    // *** 디비에 해당 유저의 issuer 조회
    // *** 디비에 저장된 해당 사용자의 issuer 과 다를 경우(null 포함)는 로그아웃 처리되었거나 잘못된 토큰
    // token의 issuer가 변경되면 이전 토큰은 모두 사용 불가(refresh token 재발급, 로그아웃..)
    if(rt_decoded.iss != global.issuer) throw {local_code:1025}

    return rt_decoded;
}

/* 토큰 디코드 */
const decodeToken = async function(token) {
    try {
        const decoded = jwt.verify(token, keyData.privateKey);
        decoded.exp2 = common.dateFormat(decoded.exp*1000); // 날짜 포맷 추가(임시)

        return decoded;
    } catch(err) {
        throw err;
    }
}

/* 토큰 타입에 따라 만료 시간 설정 */
const getTokenExpiredDate = function(type) {
    const nowDate = Math.round((new Date()).getTime()/1000);
    const exp = type == 'access_token' ? nowDate + Number(process.env.AT_EXPIRED) : nowDate + Number(process.env.RT_EXPIRED);

    return exp;
}

/* issuer data를 return */
const getIssuer = function(userId) {
    return new Promise((resolve, reject) => {
        let issuer = global.issuer; // *** DB에서 해당 사용자 issuer 을 조회
        if(issuer) {
            issuer = `${userId}_${Number(issuer.split('_')[1])+1}`
        } else {
            issuer = `${userId}_1`;
        }
        resolve(issuer)
    })
}

module.exports = {
    signToken,
    decodeTokenChk,
    isAuthenticated,
    getNewAccessToken,
    getRefreshToken,
    getIssuer
}