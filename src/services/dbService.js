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

    static async findUserById(id) {
        try {
            console.log('Finding user by ID:', id);
            const response = await axios.get(`${DB_SERVICE_URL}/users/${id}`);
            
            if (!response.data) {
                console.error('No user data returned for ID:', id);
                throw new Error('User not found');
            }
            
            console.log('User found:', { id: response.data._id, email: response.data.email });
            return response.data;
        } catch (error) {
            console.error('Error finding user by ID:', error);
            if (error.response) {
                // The request was made and the server responded with a status code
                // that falls out of the range of 2xx
                console.error('Database service error response:', {
                    status: error.response.status,
                    data: error.response.data
                });
                throw new Error(error.response.data.message || 'Error fetching user data');
            } else if (error.request) {
                // The request was made but no response was received
                console.error('No response from database service');
                throw new Error('Database service unavailable');
            } else {
                // Something happened in setting up the request that triggered an Error
                console.error('Error setting up request:', error.message);
                throw error;
            }
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