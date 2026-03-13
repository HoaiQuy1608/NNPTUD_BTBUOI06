const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const userController = require('../controllers/users');

module.exports = {
    checkLogin: async function (req, res, next) {
        let token = req.headers.authorization;
        if (!token || !token.startsWith("Bearer")) {
            return res.status(403).send("ban chua dang nhap");
        }
        token = token.split(" ")[1];
        try {
            const publicKeyPath = path.resolve(__dirname, '..', 'public.pem');
            const publicKey = fs.readFileSync(publicKeyPath, 'utf8');
            const result = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
            const user = await userController.FindById(result.id);
            
            if (!user) {
                return res.status(403).send("ban chua dang nhap");
            } else {
                req.user = user; 
                next();
            }
        } catch (error) {
            console.error("Lỗi xác thực JWT:", error.message);
            return res.status(403).send("ban chua dang nhap");
        }
    }
};