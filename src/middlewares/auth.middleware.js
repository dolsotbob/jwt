const jwt = require('jsonwebtoken');
const { secretKey } = require('../config');
const { TokenExpiredError } = require('jsonwebtoken');
const { JsonWebTokenError } = require('jsonwebtoken');

module.exports = {
  auth: (req, res, next) => {
    /*
       Todo: 요청 헤더에서 JWT를 추출하고, 토큰을 검증한 후
           verify하여 디코딩된 정보를 req.decoded에 저장합니다.
           이후 다음 프로세스를 위해 next()을 실행합니다.
     */
    /*
        Todo: err.name에 따라 조건에 맞는 응답을 반환합니다. 
          - TokenExpiredError : 419 응답코드와 함께 "토큰이 만료되었습니다."를 반환
          - JsonWebTokenError : 401 응답코드와 함께 "유효하지 않은 토큰입니다."를 반환
      */
    const authHeader = req.headers.authorization;

    // 토큰 없음 
    if (!authHeader) {
      return res.status(401).json({ message: '토큰이 없습니다.' });
    }

    const token = authHeader.split(' ')[0] === 'Bearer'
      ? authHeader.split(' ')[1]
      : authHeader;
    // console.log(token);

    try {
      // console.log(req.headers.authorization);
      const decoded = jwt.verify(token, secretKey);
      req.decoded = decoded;
      next();
    } catch (err) {
      // console.log(err.name);
      if (err.name === 'TokenExpiredError') {
        return res.status(419).json({ message: "토큰이 만료되었습니다." });
      } else if (err.name === 'JsonWebTokenError') {
        return res.status(401).json({ message: "유효하지 않은 토큰입니다." });
      } else {
        return res.status(500).json({ message: "서버 오류입니다." })
      }
    }
  },
};
