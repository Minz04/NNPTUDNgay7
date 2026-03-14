let jwt = require('jsonwebtoken');
let userController = require("../controllers/users");
const fs = require('fs');
const path = require('path');

// Đọc Public Key từ thư mục gốc
const publicKey = fs.readFileSync(path.join(__dirname, '../public.pem'), 'utf8');

module.exports = {
    checkLogin: async function (req, res, next) {
        try {
            let token = req.headers.authorization;
            if (!token || !token.startsWith('Bearer ')) {
                return res.status(401).send("Bạn chưa đăng nhập");
            }
            
            token = token.split(" ")[1];
            
            // Verify bằng Public Key và thuật toán RS256
            let result = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
            
            // Tìm user
            let user = await userController.FindUserById(result.id);
            if (user) {
                req.user = user; // Gắn thông tin user vào request
                next();
            } else {
                res.status(401).send("Bạn chưa đăng nhập");
            }
        } catch (error) {
            res.status(401).send("Token không hợp lệ hoặc đã hết hạn");
        }
    }
}