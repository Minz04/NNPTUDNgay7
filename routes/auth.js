let express = require('express');
let router = express.Router();
let userController = require('../controllers/users');

// SỬA LỖI: Thêm ChangePasswordValidator vào phần import từ file validator
let { RegisterValidator, ChangePasswordValidator, validatedResult } = require('../utils/validator');

let bcrypt = require('bcrypt');
let jwt = require('jsonwebtoken');
const { check } = require('express-validator');
const { checkLogin } = require('../utils/authHandler');

// SỬA LỖI: Khai báo thư viện fs và path của Node.js
const fs = require('fs');
const path = require('path');

// Đọc Private Key
const privateKey = fs.readFileSync(path.join(__dirname, '../private.pem'), 'utf8');

router.post('/register', RegisterValidator, validatedResult, async function (req, res, next) {
    let { username, password, email } = req.body;
    let newUser = await userController.CreateAnUser(
        username, password, email, '69b2763ce64fe93ca6985b56'
    )
    res.send(newUser)
})

router.post('/login', async function (req, res, next) {
    let { username, password } = req.body;
    let user = await userController.FindUserByUsername(username);
    
    if (!user) {
        return res.status(404).send({ message: "Thông tin đăng nhập không đúng" });
    }
    
    if (!user.lockTime || user.lockTime < Date.now()) {
        if (bcrypt.compareSync(password, user.password)) {
            user.loginCount = 0;
            await user.save();
            
            // Dùng Private Key và RS256 để Sign Token
            let token = jwt.sign({
                id: user._id,
            }, privateKey, {
                algorithm: 'RS256',
                expiresIn: '1h'
            });
            
            return res.send({ token: token });
        } else {
            user.loginCount++;
            if (user.loginCount == 3) {
                user.loginCount = 0;
                user.lockTime = new Date(Date.now() + 60 * 60 * 1000);
            }
            await user.save();
            return res.status(404).send({ message: "Thông tin đăng nhập không đúng" });
        }
    } else {
        return res.status(403).send({ message: "User đang bị khóa" });
    }
});

router.get('/me', checkLogin, function (req, res, next) {
    res.send(req.user);
});

router.post('/change-password', checkLogin, ChangePasswordValidator, validatedResult, async function (req, res, next) {
    let { oldpassword, newpassword } = req.body;
    let user = req.user; // Lấy user từ middleware checkLogin

    // Kiểm tra mật khẩu cũ có khớp không
    if (!bcrypt.compareSync(oldpassword, user.password)) {
        return res.status(400).send({ message: "Mật khẩu cũ không chính xác" });
    }

    // Gán mật khẩu mới (hook pre('save') trong schemas/users.js sẽ tự động hash mật khẩu này)
    user.password = newpassword;
    await user.save();

    res.send({ message: "Đổi mật khẩu thành công" });
});

module.exports = router;