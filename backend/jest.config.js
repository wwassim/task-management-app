module.exports = {
  testEnvironment: "node",
  coveragePathIgnorePatterns: ["/node_modules/", "/config/", "/tests/"],
  testMatch: ["**/__tests__/**/*.test.js", "**/?(*.)+(spec|test).js"],
  collectCoverageFrom: [
    "controllers/**/*.js",
    "routes/**/*.js",
    "middleware/**/*.js",
    "utils/**/*.js",
    "!**/node_modules/**",
  ],
  setupFilesAfterEnv: ["<rootDir>/tests/setup.js"],
};
