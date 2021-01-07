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
const signToken = async (req, user_id, user_type, token_type) => {

    const expired_date = getTokenExpiredDate(token_type);
    try {
        const issuer = await getIssuer();
        const tknInit = {   // 기본으로 들어갈 token 데이터
            audience: token_type, 
            issuer: issuer,
            jwtid: "1", 
            subject: "user_info" 
        };

        const tknData = {   // token에 넣을 사용자 DB 정보 데이터 지정
            user_id,
            user_type,
            expired_date
        }

        return tokenGenerator.sign(tknData, tknInit);
    } catch(error) {
        throw error
    }
};

/* 
    토큰 인증 여부 
    - refresh token 을 access token 으로 사용 방지
*/
const isAuthenticated = async function(req, res, next) {

    const token = common.isNull(req.headers.authorization, null);

    if(!token) { // Token 이 없을 경우 
        common.errorHandler(null, res, 1000);
        return;
    }

    try {
        const decoded = await decodeToken(token)
        const now = Math.floor((new Date).getTime()/1000);
        const issuer = await getIssuer();

        if(decoded.iss != issuer) {   // token의 issuer을 변경하면 이전 토큰은 모두 사용 불가
            common.errorHandler(null, res, 1025);
            return;
        }

        if(decoded.aud != 'access_token') { // refresh token 을 access token 으로 사용 방지
            common.errorHandler(null, res, 1024);
            console.log('refresh_token : ',decoded);
            return;
        }
        if(Number(now) > Number(decoded.expired_date)) { // 만료 확인
            common.errorHandler(null, res, 1003);
            return;
        }

        req.decoded = decoded;
        next()
    } catch(err) {
        if(err.message == 'invalid token') {
            common.errorHandler(null, res, 1002);
        } else {
            common.errorHandler(null, res, 1000);
        }
    }
}

/* 
    Access Token 재발급
    - Refresh token 만료 전 
*/
const getNewAccessToken = async function(req, res, next) {

    const access_token  = common.isNull(req.headers.authorization, null);
    const refresh_token = common.isNull(req.body.refresh_token, null);

    if(!access_token || !refresh_token) {
        common.errorHandler(null, res, 1000)
        return;
    }

    try {
        const at_decoded = await decodeToken(access_token);
        const rt_decoded = await decodeToken(refresh_token);

        if(at_decoded.aud != 'access_token' || rt_decoded.aud != 'refresh_token') { // 토큰 타입을 잘못 넣은 경우
            common.errorHandler(null, res, 1002)
            return;
        }

        const issuer = await getIssuer();
        if(rt_decoded.iss != issuer) {   // token의 issuer을 변경하면 이전 토큰은 모두 사용 불가
            common.errorHandler(null, res, 1025);
            return;
        }

        const now = Math.floor((new Date).getTime()/1000);
        const expired_date = Number(rt_decoded.expired_date);
        if(now > expired_date) {    // refresh token 만료 확인
            common.errorHandler(null, res, 1022);
            return;
        }

        //*** 디비에 해당 유저의 refresh token 조회
        //*** 디비에 저장된 해당 사용자의 refresh token 과 다를 경우(null 포함)는 로그아웃 처리되었거나 잘못된 토큰
        const db_token = global.db_refresh_token;   // 프로그램 재시작시 데이터 사라짐
        if(db_token != refresh_token) {
            common.errorHandler(null, res, 1023);
            return;
        }

        const new_expired_date = getTokenExpiredDate(at_decoded.aud)
        const newId = (parseInt(at_decoded.jti) + 1).toString();
        const tknInit = {   // 기본으로 들어갈 token 데이터
            audience: at_decoded.aud, 
            issuer: issuer,
            jwtid: newId, 
            subject: "user_info" 
        };
        const tknData = {   // token에 넣을 사용자 DB 정보 데이터 지정
            user_id : at_decoded.user_id,
            user_type : at_decoded.user_type,
            expired_date : new_expired_date
        }
        const new_access_token = tokenGenerator.sign(tknData, tknInit);

        res.json({
            success_yn: true,
            new_access_token
        });
        
    } catch(err) {
        if(err.message == 'invalid token') {
            common.errorHandler(null, res, 1002);
        } else {
            common.errorHandler(null, res, 1000);
        }
    }
}

/* 토큰 디코드 */
const decodeToken = async function(token) {
    try {
        const decoded = jwt.verify(token, keyData.privateKey);
        decoded.expired_formaet = common.dateFormat(decoded.expired_date*1000);
        return decoded;
    } catch(err) {
        throw err;
    }
}

/* 토큰 타입에 따라 만료 시간 설정 */
const getTokenExpiredDate = function(type) {
    const nowDate = Math.round((new Date()).getTime()/1000);
    const expired_date = type == 'access_token' ? nowDate + Number(process.env.AT_EXPIRED) : nowDate + Number(process.env.RT_EXPIRED);
    return expired_date;
}

/* 프로그램을 reboot 하지 않고도 변경된 내용 get */
const getIssuer = function() {
    return new Promise((resolve, reject) => {
        fs.readFile(INFO_PATH, 'utf8', (err, data) => {
            if(err) {
                reject(err)
            } else {
                resolve(JSON.parse(data).token_issuer);
            }
        });
    })
}

module.exports = {
    signToken,
    decodeToken,
    isAuthenticated,
    getNewAccessToken
}