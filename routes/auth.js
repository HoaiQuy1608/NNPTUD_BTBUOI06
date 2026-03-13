var express = require('express');
const fs = require('fs');
const path = require('path');
var router = express.Router();
let userController = require('../controllers/users')
let { RegisterValidator, handleResultValidator } = require('../utils/validatorHandler')
let bcrypt = require('bcrypt')
let jwt = require('jsonwebtoken')
let {checkLogin} = require('../utils/authHandler')

function sanitizeUser(user) {
    if (!user) return null;
    const userObject = user.toObject ? user.toObject() : user;
    delete userObject.password;
    return userObject;
}

router.post('/register', RegisterValidator, handleResultValidator, async function (req, res, next) {
    let newUser = userController.CreateAnUser(
        req.body.username, req.body.password, req.body.email, "69aa8360450df994c1ce6c4c"
    );
    await newUser.save()
    res.send({ message: "dang ki thanh cong" })
});

router.post('/login', async function (req, res, next) {
    let { username, password } = req.body;
    let getUser = await userController.FindByUsername(username);
    if (!getUser) {
        return res.status(403).send("tai khoan khong ton tai")
    } else {
        if (getUser.lockTime && getUser.lockTime > Date.now()) {
            return res.status(403).send("tai khoan dang bi ban");
        }
        if (bcrypt.compareSync(password, getUser.password)) {
            await userController.SuccessLogin(getUser);
            const privateKeyPath = path.resolve(__dirname, '..', 'private.pem');
            const privateKey = fs.readFileSync(privateKeyPath, 'utf8');

            const token = jwt.sign({ id: getUser._id }, privateKey, {
                algorithm: 'RS256', 
                expiresIn: '30d'
            });

            res.send({
                token: token,
                tokenType: 'Bearer'
            })
        } else {
            await userController.FailLogin(getUser);
            res.status(403).send("thong tin dang nhap khong dung")
        }
    }
});

router.get('/me', checkLogin, function(req, res, next) {
    res.send(sanitizeUser(req.user))
})

router.post('/change-password', checkLogin, async function(req, res, next) {
    let { oldPassword, newPassword } = req.body;
    if (!newPassword || newPassword.length < 6) return res.status(400).send("Mật khẩu mới quá ngắn");
    if (oldPassword === newPassword) return res.status(400).send("Trùng mật khẩu cũ");

    let user = req.user;
    if (!bcrypt.compareSync(oldPassword, user.password)) {
        return res.status(403).send("Mật khẩu cũ không chính xác");
    }

    try {
        user.password = bcrypt.hashSync(newPassword, 10);
        await user.save();
        res.send({ message: "Đổi mật khẩu thành công" });
    } catch (error) {
        res.status(500).send("Lỗi server");
    }
});

module.exports = router;