const ERROR_CODE = require('../static/error_code.json');

const isNull = (value, replace) => {
    return value == "" 
    || value == null 
    || value == undefined 
    || (value != null && typeof value == "object" && !Object.keys(value).length) ? replace : value;
}

/* 에러 핸들러 */
const errorHandler = function(err, res, code) {
    console.log('============== [errorHandler] start ===============');
    if(err) {
        console.log(err);
    } else {
        console.log(`* ERROR CODE: [ ${code} ]`);
    }
    console.log('============== [errorHandler] end   ===============');
    const codeNum = code ? code : 9000;
    const sta   = ERROR_CODE[codeNum][0];
    const msg   = ERROR_CODE[codeNum][1];
    res.status(sta).send({ success_yn: false, code, msg });
}

const dateFormat = function(mill) {
    const date = new Date(mill);
    const yy = date.getFullYear();
    const mm = date.getMonth()+1 < 10 ? '0' + (date.getMonth()+1) : date.getDate()+1;
    const dd = date.getDate() < 10 ? '0' + date.getDate() : date.getDate();
    const hh = date.getHours() < 10 ? '0' + date.getHours() : date.getHours();
    const MM = date.getMinutes() < 10 ? '0' + date.getMinutes() : date.getMinutes();
    const ss = date.getSeconds() < 10 ? '0' + date.getSeconds() : date.getSeconds();

    return `${yy}-${mm}-${dd} ${hh}:${MM}:${ss}`
}

module.exports = {
    errorHandler,
    isNull,
    dateFormat
}