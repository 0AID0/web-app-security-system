require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = 3000;

// Секретные ключи из .env
const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET;

// Промежуточное ПО
app.use(express.json());
app.use(cookieParser());

// Имитация базы данных пользователей
const users = [
    {
        id: 1,
        username: 'admin',
        password: 'admin123',
        role: 'admin'
    },
    {
        id: 2,
        username: 'user',
        password: 'user123',
        role: 'user'
    }
];

// Маршрут для входа
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    // Находим пользователя (в реальном приложении - проверка в БД)
    const user = users.find(u => u.username === username && u.password === password);
    
    if (!user) {
        return res.status(401).json({ message: 'Неверные учетные данные' });
    }
    
    // Access Token (короткоживущий)
    const accessToken = jwt.sign(
        { userId: user.id, role: user.role },
        ACCESS_TOKEN_SECRET,
        { expiresIn: '15m' }
    );
    
    // Refresh Token (долгоживущий)
    const refreshToken = jwt.sign(
        { userId: user.id },
        REFRESH_TOKEN_SECRET,
        { expiresIn: '7d' }
    );
    
    // Отправляем access token в ответе, refresh token в httpOnly cookie
    res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production', // В production должно быть true
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 дней
    }).json({ accessToken });
});

// Маршрут для обновления токена
app.post('/refresh', (req, res) => {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) {
        return res.sendStatus(401);
    }
    
    jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) {
            return res.sendStatus(403);
        }
        
        // Проверяем, существует ли пользователь (в реальном приложении - проверка в БД)
        const foundUser = users.find(u => u.id === user.userId);
        if (!foundUser) {
            return res.sendStatus(403);
        }
        
        const newAccessToken = jwt.sign(
            { userId: foundUser.id, role: foundUser.role },
            ACCESS_TOKEN_SECRET,
            { expiresIn: '15m' }
        );
        
        res.json({ accessToken: newAccessToken });
    });
});

// Защищенный маршрут (пример)
app.get('/protected', authenticateToken, (req, res) => {
    res.json({ 
        message: 'Это защищенные данные',
        user: req.user
    });
});

// Middleware для проверки JWT
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.sendStatus(401);
    }
    
    jwt.verify(token, ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) {
            return res.sendStatus(403);
        }
        req.user = user;
        next();
    });
}

// Запуск сервера
app.listen(PORT, () => {
    console.log(`Сервер запущен на порту ${PORT}`);
});