const axios = require('axios');

const DB_SERVICE_URL = 'http://localhost:5001/api';

class DatabaseService {
    static async createUser(userData) {
        try {
            const response = await axios.post(`${DB_SERVICE_URL}/users`, userData);
            return response.data;
        } catch (error) {
            console.error('Error creating user:', error);
            throw error;
        }
    }

    static async findUserById(userId) {
        try {
            const response = await axios.get(`${DB_SERVICE_URL}/users/${userId}`);
            return response.data;
        } catch (error) {
            console.error('Error finding user:', error);
            throw error;
        }
    }

    static async findUserByEmail(email) {
        try {
            const response = await axios.get(`${DB_SERVICE_URL}/users/email/${email}`);
            return response.data;
        } catch (error) {
            console.error('Error finding user by email:', error);
            throw error;
        }
    }

    static async findUserByUsername(username) {
        try {
            const response = await axios.get(`${DB_SERVICE_URL}/users/username/${username}`);
            return response.data;
        } catch (error) {
            console.error('Error finding user by username:', error);
            throw error;
        }
    }

    static async updateUser(userId, updateData) {
        try {
            const response = await axios.patch(`${DB_SERVICE_URL}/users/${userId}`, updateData);
            return response.data;
        } catch (error) {
            console.error('Error updating user:', error);
            throw error;
        }
    }

    static async findUserBySocialId(provider, socialId) {
        try {
            const response = await axios.get(`${DB_SERVICE_URL}/users/social/${provider}/${socialId}`);
            return response.data;
        } catch (error) {
            console.error('Error finding user by social ID:', error);
            throw error;
        }
    }

    static async findUserByResetToken(token) {
        try {
            const response = await axios.get(`${DB_SERVICE_URL}/users/reset-token/${token}`);
            return response.data;
        } catch (error) {
            console.error('Error finding user by reset token:', error);
            throw error;
        }
    }
}

module.exports = DatabaseService; 