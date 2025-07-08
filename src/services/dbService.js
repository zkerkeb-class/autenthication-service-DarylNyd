const axios = require('axios');
require('dotenv').config();

const DB_SERVICE_URL = process.env.DB_SERVICE_URL || 'http://localhost:5001/api';

// Configure axios with timeout and retry logic
const axiosInstance = axios.create({
    baseURL: DB_SERVICE_URL,
    timeout: 10000, // 10 second timeout
    headers: {
        'Content-Type': 'application/json'
    }
});

// Add request interceptor for logging
axiosInstance.interceptors.request.use(
    (config) => {
        console.log(`DB Service Request: ${config.method?.toUpperCase()} ${config.url}`);
        return config;
    },
    (error) => {
        console.error('DB Service Request Error:', error);
        return Promise.reject(error);
    }
);

// Add response interceptor for error handling
axiosInstance.interceptors.response.use(
    (response) => {
        return response;
    },
    (error) => {
        console.error('DB Service Response Error:', {
            status: error.response?.status,
            statusText: error.response?.statusText,
            url: error.config?.url,
            method: error.config?.method,
            message: error.message
        });
        return Promise.reject(error);
    }
);

class DatabaseService {
    static async createUser(userData) {
        try {
            const response = await axiosInstance.post('/users', userData);
            return response.data;
        } catch (error) {
            console.error('Error creating user:', error);
            // Handle duplicate user errors (409) with specific messages
            if (error.response && error.response.status === 409) {
                const errorMessage = error.response.data?.message || 'User already exists';
                console.log('User already exists - duplicate registration attempt:', errorMessage);
                throw new Error(errorMessage);
            }
            this.handleDatabaseError(error, 'createUser');
        }
    }

    static async findUserById(id) {
        try {
            console.log('Finding user by ID:', id);
            const response = await axiosInstance.get(`/users/${id}`);
            
            if (!response.data) {
                console.error('No user data returned for ID:', id);
                throw new Error('User not found');
            }
            
            console.log('User found:', { id: response.data._id, email: response.data.email });
            return response.data;
        } catch (error) {
            console.error('Error finding user by ID:', error);
            this.handleDatabaseError(error, 'findUserById', id);
        }
    }

    static async findUserByEmail(email) {
        try {
            const response = await axiosInstance.get(`/users/email/${email}`);
            return response.data;
        } catch (error) {
            // If user not found (404), return null instead of throwing error
            if (error.response && error.response.status === 404) {
                console.log(`User not found for email: ${email} - this is expected for new users`);
                return null;
            }
            console.error('Error finding user by email:', error);
            this.handleDatabaseError(error, 'findUserByEmail', email);
        }
    }

    static async findUserByUsername(username) {
        try {
            const response = await axiosInstance.get(`/users/username/${username}`);
            return response.data;
        } catch (error) {
            // If user not found (404), return null instead of throwing error
            if (error.response && error.response.status === 404) {
                console.log(`User not found for username: ${username} - this is expected for new users`);
                return null;
            }
            console.error('Error finding user by username:', error);
            this.handleDatabaseError(error, 'findUserByUsername', username);
        }
    }

    static async updateUser(userId, updateData) {
        try {
            const response = await axiosInstance.patch(`/users/${userId}`, updateData);
            return response.data;
        } catch (error) {
            console.error('Error updating user:', error);
            this.handleDatabaseError(error, 'updateUser', userId);
        }
    }

    static async findUserBySocialId(provider, socialId) {
        try {
            const response = await axiosInstance.get(`/users/social/${provider}/${socialId}`);
            return response.data;
        } catch (error) {
            // If user not found (404), return null instead of throwing error
            if (error.response && error.response.status === 404) {
                console.log(`User not found for ${provider}:${socialId} - this is expected for new users`);
                return null;
            }
            console.error('Error finding user by social ID:', error);
            this.handleDatabaseError(error, 'findUserBySocialId', `${provider}:${socialId}`);
        }
    }

    static async findUserByResetToken(token) {
        try {
            const response = await axiosInstance.get(`/users/reset-token/${token}`);
            return response.data;
        } catch (error) {
            console.error('Error finding user by reset token:', error);
            this.handleDatabaseError(error, 'findUserByResetToken');
        }
    }

    // Centralized error handling method
    static handleDatabaseError(error, operation, identifier = '') {
        const errorInfo = {
            operation,
            identifier,
            timestamp: new Date().toISOString()
        };

        if (error.response) {
            // The request was made and the server responded with a status code
            // that falls out of the range of 2xx
            const status = error.response.status;
            const data = error.response.data;

            console.error('Database service error response:', {
                ...errorInfo,
                status,
                data
            });

            switch (status) {
                case 404:
                    throw new Error('Resource not found');
                case 400:
                    throw new Error(data.message || 'Bad request');
                case 401:
                    throw new Error('Unauthorized access to database');
                case 403:
                    throw new Error('Forbidden access to database');
                case 409:
                    throw new Error(data.message || 'Resource conflict');
                case 422:
                    throw new Error(data.message || 'Validation error');
                case 500:
                    throw new Error('Database service internal error');
                default:
                    throw new Error(data.message || `Database service error: ${status}`);
            }
        } else if (error.request) {
            // The request was made but no response was received
            console.error('No response from database service:', errorInfo);
            throw new Error('Database service unavailable - no response received');
        } else {
            // Something happened in setting up the request that triggered an Error
            console.error('Error setting up database request:', {
                ...errorInfo,
                message: error.message
            });
            throw new Error(`Database service request error: ${error.message}`);
        }
    }

    // Health check method
    static async healthCheck() {
        try {
            const response = await axiosInstance.get('/health');
            return {
                status: 'healthy',
                data: response.data
            };
        } catch (error) {
            console.error('Database service health check failed:', error);
            return {
                status: 'unhealthy',
                error: error.message
            };
        }
    }
}

module.exports = DatabaseService; 