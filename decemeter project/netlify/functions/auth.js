const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Client } = require('pg');

// JWT Secret from environment variables
const JWT_SECRET = process.env.JWT_SECRET || 'your-production-secret-key-change-this';
const JWT_EXPIRES_IN = '7d';

// Database connection
const getDBClient = () => {
  return new Client({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
  });
};

exports.handler = async (event, context) => {
  // Set CORS headers
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Content-Type': 'application/json'
  };

  // Handle preflight
  if (event.httpMethod === 'OPTIONS') {
    return {
      statusCode: 200,
      headers,
      body: ''
    };
  }

  // Only accept POST requests
  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ success: false, error: 'Method not allowed' })
    };
  }

  try {
    const data = JSON.parse(event.body);
    const { action, email, password, firstName, lastName, phone, token } = data;

    console.log(`Auth action: ${action} for ${email}`);

    switch (action) {
      case 'register':
        return await handleRegister(email, password, firstName, lastName, phone);
      case 'login':
        return await handleLogin(email, password);
      case 'verify':
        return await handleVerify(token);
      case 'update-profile':
        return await handleUpdateProfile(token, data);
      case 'change-password':
        return await handleChangePassword(token, data);
      default:
        return {
          statusCode: 400,
          headers,
          body: JSON.stringify({ success: false, error: 'Invalid action' })
        };
    }
  } catch (error) {
    console.error('Auth error:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ 
        success: false, 
        error: 'Internal server error',
        message: error.message 
      })
    };
  }
};

// Helper function to validate email format
function validateEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
}

// Helper function to generate JWT token
function generateToken(userId, email) {
  return jwt.sign(
    { 
      userId, 
      email,
      exp: Math.floor(Date.now() / 1000) + (7 * 24 * 60 * 60) // 7 days
    },
    JWT_SECRET
  );
}

// Register new user
async function handleRegister(email, password, firstName, lastName, phone) {
  const client = getDBClient();
  
  try {
    await client.connect();

    // Validate input
    if (!email || !password || !firstName || !lastName) {
      return {
        statusCode: 400,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ success: false, error: 'All fields are required' })
      };
    }

    if (!validateEmail(email)) {
      return {
        statusCode: 400,
        body: JSON.stringify({ success: false, error: 'Invalid email format' })
      };
    }

    if (password.length < 8) {
      return {
        statusCode: 400,
        body: JSON.stringify({ success: false, error: 'Password must be at least 8 characters' })
      };
    }

    // Check if user already exists
    const existingUser = await client.query(
      'SELECT id FROM users WHERE email = $1',
      [email.toLowerCase()]
    );

    if (existingUser.rows.length > 0) {
      return {
        statusCode: 409,
        body: JSON.stringify({ success: false, error: 'Email already registered' })
      };
    }

    // Hash password
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    // Insert new user
    const result = await client.query(
      `INSERT INTO users (email, password_hash, first_name, last_name, phone) 
       VALUES ($1, $2, $3, $4, $5) 
       RETURNING id, email, first_name, last_name, phone, created_at`,
      [email.toLowerCase(), passwordHash, firstName, lastName, phone || null]
    );

    const user = result.rows[0];
    
    // Generate JWT token
    const token = generateToken(user.id, user.email);

    return {
      statusCode: 201,
      body: JSON.stringify({
        success: true,
        message: 'Account created successfully',
        user: {
          id: user.id,
          email: user.email,
          name: `${user.first_name} ${user.last_name}`,
          firstName: user.first_name,
          lastName: user.last_name,
          phone: user.phone
        },
        token
      })
    };

  } catch (error) {
    console.error('Registration error:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ 
        success: false, 
        error: 'Registration failed',
        details: error.message 
      })
    };
  } finally {
    await client.end();
  }
}

// Login user
async function handleLogin(email, password) {
  const client = getDBClient();
  
  try {
    await client.connect();

    if (!email || !password) {
      return {
        statusCode: 400,
        body: JSON.stringify({ success: false, error: 'Email and password are required' })
      };
    }

    // Find user
    const result = await client.query(
      `SELECT id, email, password_hash, first_name, last_name, phone 
       FROM users WHERE email = $1`,
      [email.toLowerCase()]
    );

    if (result.rows.length === 0) {
      return {
        statusCode: 401,
        body: JSON.stringify({ success: false, error: 'Invalid email or password' })
      };
    }

    const user = result.rows[0];

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
      return {
        statusCode: 401,
        body: JSON.stringify({ success: false, error: 'Invalid email or password' })
      };
    }

    // Generate JWT token
    const token = generateToken(user.id, user.email);

    // Update last login (optional - you can add this field to users table)
    await client.query(
      'UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = $1',
      [user.id]
    );

    return {
      statusCode: 200,
      body: JSON.stringify({
        success: true,
        message: 'Login successful',
        user: {
          id: user.id,
          email: user.email,
          name: `${user.first_name} ${user.last_name}`,
          firstName: user.first_name,
          lastName: user.last_name,
          phone: user.phone
        },
        token
      })
    };

  } catch (error) {
    console.error('Login error:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ 
        success: false, 
        error: 'Login failed',
        details: error.message 
      })
    };
  } finally {
    await client.end();
  }
}

// Verify JWT token
async function handleVerify(token) {
  try {
    if (!token) {
      return {
        statusCode: 401,
        body: JSON.stringify({ success: false, error: 'No token provided' })
      };
    }

    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const client = getDBClient();
    await client.connect();

    // Check if user still exists
    const result = await client.query(
      'SELECT id, email, first_name, last_name, phone FROM users WHERE id = $1',
      [decoded.userId]
    );

    if (result.rows.length === 0) {
      return {
        statusCode: 401,
        body: JSON.stringify({ success: false, error: 'User not found' })
      };
    }

    const user = result.rows[0];

    await client.end();

    return {
      statusCode: 200,
      body: JSON.stringify({
        success: true,
        user: {
          id: user.id,
          email: user.email,
          name: `${user.first_name} ${user.last_name}`,
          firstName: user.first_name,
          lastName: user.last_name,
          phone: user.phone
        }
      })
    };

  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return {
        statusCode: 401,
        body: JSON.stringify({ success: false, error: 'Invalid token' })
      };
    }
    if (error.name === 'TokenExpiredError') {
      return {
        statusCode: 401,
        body: JSON.stringify({ success: false, error: 'Token expired' })
      };
    }
    
    console.error('Token verification error:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ success: false, error: 'Token verification failed' })
    };
  }
}

// Update user profile
async function handleUpdateProfile(token, data) {
  const client = getDBClient();
  
  try {
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    await client.connect();

    const { firstName, lastName, phone } = data;

    // Update user
    await client.query(
      `UPDATE users 
       SET first_name = COALESCE($1, first_name),
           last_name = COALESCE($2, last_name),
           phone = COALESCE($3, phone),
           updated_at = CURRENT_TIMESTAMP
       WHERE id = $4`,
      [firstName, lastName, phone, decoded.userId]
    );

    // Get updated user
    const result = await client.query(
      'SELECT id, email, first_name, last_name, phone FROM users WHERE id = $1',
      [decoded.userId]
    );

    const user = result.rows[0];

    await client.end();

    return {
      statusCode: 200,
      body: JSON.stringify({
        success: true,
        message: 'Profile updated successfully',
        user: {
          id: user.id,
          email: user.email,
          name: `${user.first_name} ${user.last_name}`,
          firstName: user.first_name,
          lastName: user.last_name,
          phone: user.phone
        }
      })
    };

  } catch (error) {
    console.error('Update profile error:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ 
        success: false, 
        error: 'Profile update failed',
        details: error.message 
      })
    };
  } finally {
    await client.end();
  }
}

// Change password
async function handleChangePassword(token, data) {
  const client = getDBClient();
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const { currentPassword, newPassword } = data;

    if (!currentPassword || !newPassword) {
      return {
        statusCode: 400,
        body: JSON.stringify({ success: false, error: 'Both passwords are required' })
      };
    }

    if (newPassword.length < 8) {
      return {
        statusCode: 400,
        body: JSON.stringify({ success: false, error: 'New password must be at least 8 characters' })
      };
    }

    await client.connect();

    // Get current password hash
    const userResult = await client.query(
      'SELECT password_hash FROM users WHERE id = $1',
      [decoded.userId]
    );

    if (userResult.rows.length === 0) {
      return {
        statusCode: 404,
        body: JSON.stringify({ success: false, error: 'User not found' })
      };
    }

    const currentHash = userResult.rows[0].password_hash;

    // Verify current password
    const isValid = await bcrypt.compare(currentPassword, currentHash);
    if (!isValid) {
      return {
        statusCode: 401,
        body: JSON.stringify({ success: false, error: 'Current password is incorrect' })
      };
    }

    // Hash new password
    const salt = await bcrypt.genSalt(12);
    const newHash = await bcrypt.hash(newPassword, salt);

    // Update password
    await client.query(
      'UPDATE users SET password_hash = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
      [newHash, decoded.userId]
    );

    await client.end();

    return {
      statusCode: 200,
      body: JSON.stringify({
        success: true,
        message: 'Password changed successfully'
      })
    };

  } catch (error) {
    console.error('Change password error:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ 
        success: false, 
        error: 'Password change failed',
        details: error.message 
      })
    };
  } finally {
    await client.end();
  }
}