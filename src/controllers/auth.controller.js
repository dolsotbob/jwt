const jwt = require('jsonwebtoken');
const { findUserByUserId, verifyUser } = require('../services/auth.service');
const { secretKey } = require('../config');
// const jsonwebtoken = require('jsonwebtoken');

module.exports = {
  login: async (req, res) => {
    const { userId, password } = req.body;
    /*
      Todo: verifyUser 함수를 통해 유저임을 확인합니다.
        - 유저가 아닐 경우, 401 응답코드와 함께 message의 값으로 '등록되지 않은 유저입니다.'를 반환
        - 유저일 경우, 
            토큰을 생성하여
            200 응답코드와 함께 token의 값으로 토큰을 반환
    */
    // 필수 입력 체크 
    if (!userId || !password) {
      return res.status(401).json({ message: '등록되지 않은 유저입니다.' });
    }

    // 유저 확인 
    // verifyUser 함수는 src/services/auth.service.js에 있음 
    const isValidUser = await verifyUser(userId, password);
    if (!isValidUser) {
      return res.status(401).json({ message: '등록되지 않은 유저입니다.' });
    }

    // 토큰 생성 
    // sign 눌러서 뭐를 인자로 쓸지 확인하면 됨 
    const token = jwt.sign({ userId }, secretKey, {
      expiresIn: '15m',
      issuer: 'jwt-issuer',
    });
    // console.log(token);

    return res.status(200).json({ token });
  },

  // 토큰 없으면 401, 토큰 있으면 userId 기반 유저 정보 반환
  me: async (req, res) => {
    const { userId } = req.decoded;
    /*
      Todo: findUserByUserId 함수를 통해 유저 정보를 찾아
        200 응답코드와 함께 user의 값으로 유저 정보를 반환합니다.
        - 반환해야 하는 데이터 양식은 테스트 코드를 통해 확인합니다.
    */
    const user = await findUserByUserId(userId);
    if (!user) {
      return res.status(404).json({ message: '유저를 찾을 수 없습니다.' });
    }

    return res.status(200).json({ user });
  },
};
