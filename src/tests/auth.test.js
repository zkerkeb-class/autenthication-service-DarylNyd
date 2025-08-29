const fetch = require('node-fetch');

async function testAuthService() {
    console.log('Testing Authentication Service...\n');

    // Test 1: Health check
    try {
        const healthResponse = await fetch('http://localhost:5002/health');
        const healthData = await healthResponse.json();
        console.log('✅ Health check:', healthData);
    } catch (error) {
        console.log('❌ Health check failed:', error.message);
    }

    // Test 2: CORS preflight
    try {
        const corsResponse = await fetch('http://localhost:5002/auth/me', {
            method: 'OPTIONS',
            headers: {
                'Origin': 'http://localhost:3000',
                'Access-Control-Request-Method': 'GET',
                'Access-Control-Request-Headers': 'Authorization'
            }
        });
        console.log('✅ CORS preflight:', corsResponse.status, corsResponse.statusText);
        console.log('CORS headers:', {
            'Access-Control-Allow-Origin': corsResponse.headers.get('Access-Control-Allow-Origin'),
            'Access-Control-Allow-Methods': corsResponse.headers.get('Access-Control-Allow-Methods'),
            'Access-Control-Allow-Headers': corsResponse.headers.get('Access-Control-Allow-Headers')
        });
    } catch (error) {
        console.log('❌ CORS preflight failed:', error.message);
    }

    // Test 3: Registration endpoint
    try {
        const registerResponse = await fetch('http://localhost:5002/auth/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Origin': 'http://localhost:3000'
            },
            body: JSON.stringify({
                username: 'testuser',
                email: 'test@example.com',
                password: 'TestPass123'
            })
        });
        console.log('✅ Registration endpoint:', registerResponse.status, registerResponse.statusText);
        
        if (registerResponse.ok) {
            const data = await registerResponse.json();
            console.log('Registration response:', data);
        } else {
            const error = await registerResponse.text();
            console.log('Registration error:', error);
        }
    } catch (error) {
        console.log('❌ Registration failed:', error.message);
    }

    // Test 4: Login endpoint
    try {
        const loginResponse = await fetch('http://localhost:5002/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Origin': 'http://localhost:3000'
            },
            body: JSON.stringify({
                email: 'test@example.com',
                password: 'TestPass123'
            })
        });
        console.log('✅ Login endpoint:', loginResponse.status, loginResponse.statusText);
        
        if (loginResponse.ok) {
            const data = await loginResponse.json();
            console.log('Login successful, token length:', data.token?.length || 0);
            
            // Test 5: Get current user with token
            if (data.token) {
                const meResponse = await fetch('http://localhost:5002/auth/me', {
                    method: 'GET',
                    headers: {
                        'Authorization': `Bearer ${data.token}`,
                        'Origin': 'http://localhost:3000'
                    }
                });
                console.log('✅ Get current user:', meResponse.status, meResponse.statusText);
                
                if (meResponse.ok) {
                    const userData = await meResponse.json();
                    console.log('User data:', userData);
                } else {
                    const error = await meResponse.text();
                    console.log('Get current user error:', error);
                }
            }
        } else {
            const error = await loginResponse.text();
            console.log('Login error:', error);
        }
    } catch (error) {
        console.log('❌ Login failed:', error.message);
    }
}

testAuthService().catch(console.error); 