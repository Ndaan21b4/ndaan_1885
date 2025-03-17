var express = require('express');
var router = express.Router();
let userController = require('../controllers/users');
const { check_authentication } = require('../Utils/check_auth');
const bcrypt = require('bcrypt'); // Dùng để so sánh mật khẩu

// Đăng ký
router.post('/signup', async function(req, res, next) {
    try {
        let { username, password, email } = req.body;
        let result = await userController.createUser(username, password, email, 'user');
        res.status(200).send({ success: true, data: result });
    } catch (error) {
        next(error);
    }
});

// Đăng nhập
router.post('/login', async function(req, res, next) {
    try {
        let { username, password } = req.body;
        let result = await userController.checkLogin(username, password);
        res.status(200).send({ success: true, data: result });
    } catch (error) {
        next(error);
    }
});

// Reset mật khẩu (Chỉ Admin)
router.get('/resetPassword/:id', check_authentication, async function(req, res, next) {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).send({ success: false, message: 'Access denied' });
        }

        let userId = req.params.id;
        let newPassword = '123456';

        let result = await userController.resetPassword(userId, newPassword);
        if (!result) {
            return res.status(404).send({ success: false, message: 'User not found' });
        }

        res.status(200).send({ success: true, message: 'Password reset successfully', data: result });
    } catch (error) {
        next(error);
    }
});

// Đổi mật khẩu (Yêu cầu đăng nhập)
router.post('/changePassword', check_authentication, async function(req, res, next) {
    try {
        let userId = req.user.id;
        let { currentPassword, newPassword } = req.body;

        // Lấy thông tin user từ database
        let user = await userController.getUserById(userId);
        if (!user) {
            return res.status(404).send({ success: false, message: 'User not found' });
        }

        // Kiểm tra password hiện tại
        let match = await bcrypt.compare(currentPassword, user.password);
        if (!match) {
            return res.status(400).send({ success: false, message: 'Current password is incorrect' });
        }

        // Cập nhật password mới
        let result = await userController.changePassword(userId, newPassword);
        res.status(200).send({ success: true, message: 'Password changed successfully', data: result });

    } catch (error) {
        next(error);
    }
});

// Lấy thông tin người dùng
router.get('/me', check_authentication, async function(req, res, next) {
    try {
        res.status(200).send({ success: true, data: req.user });
    } catch (error) {
        next(error);
    }
});

module.exports = router;
