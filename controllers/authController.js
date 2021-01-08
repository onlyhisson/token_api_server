const common = require("../lib/common");
const auth = require("../middleware/auth");
const USER_INFO = { db_id: 'test', db_pw: '1234' }
const USER_TYPE_LIST = ['partner', 'user', 'admin']

/*
    title   : 로그인
    return  : 유저 정보, 토큰 정보

    - 유저 개인 정보는 이 때 한번만 응답하고 토큰에는 넣지 않는다.
*/
const postLogin = async (req, res) => {
    
    const user_id = common.isNull(req.body.user_id, null);
    const user_pw = common.isNull(req.body.user_pw, null);
    const user_type = common.isNull(req.body.user_type, null);  // partner, user, admin

    // 파리미터 확인
    if(!user_id || !user_pw || !user_type) {
        common.errorHandler(null, res, 1000);
        return;
    }
    
    // 잘못된 사용자 타입의 경우
    if(!USER_TYPE_LIST.includes(user_type)) {
        common.errorHandler(null, res, 1000);
        return;
    }

    try {
        // *** 해당 아이디 사용자 조회
        if (user_id != USER_INFO.db_id) {   // 사용자 아이디 확인
            common.errorHandler(null, res, 1006); //not exist user
            return;
        }
        if (user_pw != USER_INFO.db_pw) {   // 사용자 비번 확인
            common.errorHandler(null, res, 1007); //wrong password
            return;
        }

        const issuer = await auth.getIssuer(user_id); // *** 실제로는 DB 조회
        global.issuer = issuer; // *** DB 있을 경우 삭제 라인

        // *** 사용자 DB row 에 issuer을 update 한다.
        // *** 기타 사용자 정보를 DB에서 조회 후 응답 데이터에 추가 한다.

        const params = {user_id, user_type, issuer}
        const access_token  = await auth.signToken(params, 'access_token');
        const refresh_token = await auth.signToken(params, 'refresh_token' );
        
        res.json({
            success_yn : true,
            access_token : access_token,
            refresh_token : refresh_token
            // 추가 user 정보
        })
        
    } catch (err) {
        common.errorHandler(err, res, 8000); 
    }
}

const endFunc = async (req, res) => {
    res.json({
        success_yn : true
    })
}

const decodeToken = async (req, res) => {
    res.json({
        success_yn : true,
        decode: req.decoded
    })
}

module.exports = {
    postLogin,
    endFunc,
    decodeToken
};