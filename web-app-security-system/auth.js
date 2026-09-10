// auth.js - основной модуль для работы с JWT на клиенте
class AuthService {
    constructor() {
      this.initAuth();
    }
  
    // Хранение токена
    storeToken(token) {
      localStorage.setItem('accessToken', token);
    }
  
    // Удаление токена
    removeToken() {
      localStorage.removeItem('accessToken');
    }
  
    // Проверка наличия токена
    hasToken() {
      return !!this.getToken();
    }
  
    // Получение токена
    getToken() {
      return localStorage.getItem('accessToken');
    }
  
    // Выход из системы
    logout() {
      this.removeToken();
      // Дополнительные действия при выходе
      window.location.href = '/login';
    }
  
    // Проверка срока действия токена
    isTokenExpired(token) {
      try {
        const payload = this.decodeToken(token);
        if (payload?.exp && payload.exp < Date.now() / 1000) {
          return true;
        }
        return false;
      } catch {
        return true;
      }
    }
  
    // Декодирование токена
    decodeToken(token) {
      try {
        return JSON.parse(atob(token.split('.')[1]));
      } catch {
        return null;
      }
    }
  
    // Получение данных из токена
    getTokenData() {
      const token = this.getToken();
      return token ? this.decodeToken(token) : null;
    }
  
    // Обновление токена
    async refreshToken() {
      try {
        const response = await fetch('/api/refresh', {
          method: 'POST',
          credentials: 'include'
        });
  
        if (response.ok) {
          const { accessToken } = await response.json();
          this.storeToken(accessToken);
          return accessToken;
        }
        return null;
      } catch (error) {
        console.error('Refresh token failed:', error);
        return null;
      }
    }
  
    // Авторизованный fetch
    async fetchWithAuth(url, options = {}) {
      let token = this.getToken();
      
      if (!token) {
        throw new Error('No token found');
      }
  
      // Проверяем срок действия токена перед запросом
      if (this.isTokenExpired(token)) {
        token = await this.refreshToken();
        if (!token) {
          this.logout();
          throw new Error('Session expired');
        }
      }
  
      const headers = {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
        ...options.headers
      };
  
      const response = await fetch(url, {
        ...options,
        headers,
        credentials: 'include'
      });
  
      // Если токен истек во время запроса
      if (response.status === 401) {
        const newToken = await this.refreshToken();
        if (newToken) {
          headers.Authorization = `Bearer ${newToken}`;
          return fetch(url, { ...options, headers });
        }
        this.logout();
        throw new Error('Session expired. Please login again.');
      }
  
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
  
      return response;
    }
  
    // Инициализация при загрузке приложения
    initAuth() {
      const token = this.getToken();
      if (token && this.isTokenExpired(token)) {
        this.refreshToken().catch(() => this.logout());
      }
    }
  }
  
  // Создаем экземпляр для использования
  const authService = new AuthService();
  
  // Пример использования
  async function loadProtectedData() {
    try {
      const response = await authService.fetchWithAuth('/api/protected');
      const data = await response.json();
      console.log('Protected data:', data);
      return data;
    } catch (error) {
      console.error('Error loading protected data:', error);
      throw error;
    }
  }
  
  // Интеграция с React/Vue/Angular
  // Пример для React:
  /*
  import { useEffect, useState } from 'react';
  
  function ProtectedComponent() {
    const [data, setData] = useState(null);
    const [error, setError] = useState(null);
  
    useEffect(() => {
      loadProtectedData()
        .then(setData)
        .catch(setError);
    }, []);
  
    if (error) return <div>Error: {error.message}</div>;
    if (!data) return <div>Loading...</div>;
    
    return <div>{JSON.stringify(data)}</div>;
  }
  */
  
  // Экспортируем методы для использования
  export {
    authService,
    loadProtectedData
  };