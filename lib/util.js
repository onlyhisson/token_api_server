function isNull(data, replace) {
    return data === undefined || data === "" ? replace : data;
}

module.exports = {
    isNull,
};
