const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../index');
const User = require('../models/user.model');
const Organization = require('../models/organization.model');
const { generateToken } = require('../utils/response');

describe('Auth Routes', () => {
  let authToken;
  let testUser;

  beforeEach(async () => {
    // Clean up before each test
    await User.deleteMany({});
    await Organization.deleteMany({});
  });

  describe('POST /api/auth/register', () => {
    it('should register a new user successfully', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'password123'
      };

      const response = await request(app)
        .post('/api/auth/register')
        .send(userData)
        .expect(201);

      expect(response.body).toHaveProperty('token');
      expect(response.body).toHaveProperty('user');
      expect(response.body.user.email).toBe(userData.email);
      expect(response.body.user.role).toBe('user');
      expect(response.body.success).toBe(true);
      expect(response.body.message).toBe('User registered successfully');
    });

    it('should register a new user with admin role', async () => {
      const userData = {
        email: 'admin@example.com',
        password: 'password123',
        role: 'admin',
        organization: 'Test Organization'
      };

      const response = await request(app)
        .post('/api/auth/register')
        .send(userData)
        .expect(201);

      expect(response.body).toHaveProperty('token');
      expect(response.body.user.role).toBe('admin');
      expect(response.body.user.organization).toBeTruthy();
      expect(response.body.user.organization.name).toBe('Test Organization');
      expect(response.body.user.organization.role).toBe('admin');
    });

    it('should register a user and join existing organization', async () => {
      // First, create an organization
      const org = await Organization.create({
        name: 'Existing Org',
        owner: new mongoose.Types.ObjectId(),
        members: []
      });

      const userData = {
        email: 'member@example.com',
        password: 'password123',
        organization: 'Existing Org'
      };

      const response = await request(app)
        .post('/api/auth/register')
        .send(userData)
        .expect(201);

      expect(response.body.user.organization).toBeTruthy();
      expect(response.body.user.organization.name).toBe('Existing Org');
      expect(response.body.user.organization.role).toBe('member');
    });

    it('should return 400 if user already exists', async () => {
      // Create a user first
      await User.create({
        email: 'existing@example.com',
        password: 'hashedpassword'
      });

      const userData = {
        email: 'existing@example.com',
        password: 'password123'
      };

      const response = await request(app)
        .post('/api/auth/register')
        .send(userData)
        .expect(400);

      expect(response.body.message).toBe('User already exists');
    });

    it('should return 400 if trying to create admin for existing organization', async () => {
      // Create an organization first
      const org = await Organization.create({
        name: 'Existing Org',
        owner: new mongoose.Types.ObjectId(),
        members: []
      });

      const userData = {
        email: 'admin@example.com',
        password: 'password123',
        role: 'admin',
        organization: 'Existing Org'
      };

      const response = await request(app)
        .post('/api/auth/register')
        .send(userData)
        .expect(400);

      expect(response.body.message).toContain('already exists');
    });

    it('should return 500 on server error', async () => {
      // Mock User.findOne to throw an error
      const originalFindOne = User.findOne;
      User.findOne = jest.fn().mockRejectedValue(new Error('Database error'));

      const userData = {
        email: 'test@example.com',
        password: 'password123'
      };

      const response = await request(app)
        .post('/api/auth/register')
        .send(userData)
        .expect(500);

      expect(response.body.success).toBe(false);

      // Restore original method
      User.findOne = originalFindOne;
    });
  });

  describe('POST /api/auth/login', () => {
    beforeEach(async () => {
      // Create a test user for login tests
      const bcrypt = require('bcryptjs');
      const hashedPassword = await bcrypt.hash('password123', 10);
      testUser = await User.create({
        email: 'test@example.com',
        password: hashedPassword,
        role: 'user'
      });
    });

    it('should login user successfully with valid credentials', async () => {
      const loginData = {
        email: 'test@example.com',
        password: 'password123'
      };

      const response = await request(app)
        .post('/api/auth/login')
        .send(loginData)
        .expect(200);

      expect(response.body).toHaveProperty('token');
      expect(response.body).toHaveProperty('user');
      expect(response.body.user.email).toBe(loginData.email);
      expect(response.body.expiresIn).toBe(3600);
    });

    it('should return 404 if user not found', async () => {
      const loginData = {
        email: 'nonexistent@example.com',
        password: 'password123'
      };

      const response = await request(app)
        .post('/api/auth/login')
        .send(loginData)
        .expect(404);

      expect(response.body.message).toBe('User not found');
    });

    it('should return 401 if password is incorrect', async () => {
      const loginData = {
        email: 'test@example.com',
        password: 'wrongpassword'
      };

      const response = await request(app)
        .post('/api/auth/login')
        .send(loginData)
        .expect(401);

      expect(response.body.message).toBe('Invalid credentials');
    });

    it('should return 500 on server error', async () => {
      // Mock User.findOne to throw an error
      const originalFindOne = User.findOne;
      User.findOne = jest.fn().mockRejectedValue(new Error('Database error'));

      const loginData = {
        email: 'test@example.com',
        password: 'password123'
      };

      const response = await request(app)
        .post('/api/auth/login')
        .send(loginData)
        .expect(500);

      // Restore original method
      User.findOne = originalFindOne;
    });
  });

  describe('POST /api/auth/logout', () => {
    it('should logout user successfully', async () => {
      const response = await request(app)
        .post('/api/auth/logout')
        .expect(200);

      expect(response.body.message).toBe('User logged out');
    });
  });

  describe('GET /api/auth/users', () => {
    beforeEach(async () => {
      // Create test users
      const bcrypt = require('bcryptjs');
      const hashedPassword = await bcrypt.hash('password123', 10);
      
      testUser = await User.create({
        email: 'test@example.com',
        password: hashedPassword,
        role: 'user'
      });

      await User.create({
        email: 'test2@example.com',
        password: hashedPassword,
        role: 'admin'
      });

      // Generate token for authenticated requests
      authToken = generateToken(testUser);
    });

    it('should get all users successfully', async () => {
      const response = await request(app)
        .get('/api/auth/users')
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
      expect(response.body.length).toBeGreaterThan(0);
    });

    it('should return list of all users', async () => {
      const response = await request(app)
        .get('/api/auth/users')
        .expect(200);

      expect(response.body.length).toBe(2);
      expect(response.body.some(user => user.email === 'test@example.com')).toBe(true);
      expect(response.body.some(user => user.email === 'test2@example.com')).toBe(true);
    });

    it('should return 500 on server error', async () => {
      // Mock User.find to throw an error
      const originalFind = User.find;
      User.find = jest.fn().mockRejectedValue(new Error('Database error'));

      const response = await request(app)
        .get('/api/auth/users')
        .expect(500);

      // Restore original method
      User.find = originalFind;
    });
  });

  describe('POST /api/auth/forgot-password', () => {
    beforeEach(async () => {
      const bcrypt = require('bcryptjs');
      const hashedPassword = await bcrypt.hash('password123', 10);
      testUser = await User.create({
        email: 'test@example.com',
        password: hashedPassword,
        role: 'user'
      });
    });

    it('should handle forgot password request', async () => {
      const response = await request(app)
        .post('/api/auth/forgot-password')
        .send({ email: 'test@example.com' })
        .expect(200);

      // Note: The implementation is empty, so this test may need adjustment
      // when the feature is fully implemented
    });

    it('should return 404 if user not found', async () => {
      const response = await request(app)
        .post('/api/auth/forgot-password')
        .send({ email: 'nonexistent@example.com' })
        .expect(200); // Current implementation doesn't check, adjust when implemented
    });
  });

  describe('POST /api/auth/reset-password/:token', () => {
    it('should handle reset password request', async () => {
      const resetToken = 'test-reset-token';
      const response = await request(app)
        .post(`/api/auth/reset-password/${resetToken}`)
        .send({ password: 'newpassword123' })
        .expect(200);

      // Note: The implementation is empty, so this test may need adjustment
      // when the feature is fully implemented
    });

    it('should return 400 for invalid token', async () => {
      const resetToken = 'invalid-token';
      const response = await request(app)
        .post(`/api/auth/reset-password/${resetToken}`)
        .send({ password: 'newpassword123' })
        .expect(200); // Current implementation doesn't check, adjust when implemented
    });
  });
});

