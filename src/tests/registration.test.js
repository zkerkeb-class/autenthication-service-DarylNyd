const fetch = require('node-fetch');

async function testRegistration() {
    console.log('Testing Registration Flow...\n');

    const testEmail = `test${Date.now()}@example.com`;
    const testUsername = `testuser${Date.now()}`;
    const testPassword = 'TestPass123';

    console.log(`Testing with email: ${testEmail}`);
    console.log(`Testing with username: ${testUsername}\n`);

    // Test 1: Check if user exists before registration
    try {
        const checkEmailResponse = await fetch(`http://localhost:5001/api/users/email/${testEmail}`);
        if (checkEmailResponse.ok) {
            console.log('❌ User already exists with this email before registration');
        } else {
            console.log('✅ Email is available for registration');
        }
    } catch (error) {
        console.log('✅ Email is available for registration (404 expected)');
    }

    try {
        const checkUsernameResponse = await fetch(`http://localhost:5001/api/users/username/${testUsername}`);
        if (checkUsernameResponse.ok) {
            console.log('❌ Username already exists before registration');
        } else {
            console.log('✅ Username is available for registration');
        }
    } catch (error) {
        console.log('✅ Username is available for registration (404 expected)');
    }

    // Test 2: Register new user
    try {
        const registerResponse = await fetch('http://localhost:5002/auth/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Origin': 'http://localhost:3000'
            },
            body: JSON.stringify({
                username: testUsername,
                email: testEmail,
                password: testPassword
            })
        });

        console.log('\nRegistration response:', registerResponse.status, registerResponse.statusText);
        
        if (registerResponse.ok) {
            const data = await registerResponse.json();
            console.log('✅ Registration successful');
            console.log('User ID:', data.user?.id);
            console.log('Token length:', data.token?.length || 0);
            
            // Test 3: Verify user exists in database
            try {
                const verifyResponse = await fetch(`http://localhost:5001/api/users/email/${testEmail}`);
                if (verifyResponse.ok) {
                    const userData = await verifyResponse.json();
                    console.log('✅ User verified in database');
                    console.log('Database user ID:', userData._id);
                    console.log('Database email:', userData.email);
                    console.log('Database username:', userData.username);
                } else {
                    console.log('❌ User not found in database after registration');
                }
            } catch (error) {
                console.log('❌ Error verifying user in database:', error.message);
            }
            
        } else {
            const error = await registerResponse.text();
            console.log('❌ Registration failed:', error);
        }
    } catch (error) {
        console.log('❌ Registration request failed:', error.message);
    }

    // Test 4: Try to register the same user again (should fail)
    console.log('\n--- Testing Duplicate Registration ---');
    try {
        const duplicateResponse = await fetch('http://localhost:5002/auth/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Origin': 'http://localhost:3000'
            },
            body: JSON.stringify({
                username: testUsername,
                email: testEmail,
                password: testPassword
            })
        });

        console.log('Duplicate registration response:', duplicateResponse.status, duplicateResponse.statusText);
        
        if (duplicateResponse.status === 400 || duplicateResponse.status === 409) {
            const error = await duplicateResponse.text();
            console.log('✅ Duplicate registration correctly rejected:', error);
        } else {
            console.log('❌ Duplicate registration should have been rejected');
        }
    } catch (error) {
        console.log('❌ Duplicate registration request failed:', error.message);
    }
}

testRegistration().catch(console.error); 