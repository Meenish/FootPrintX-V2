import js from '@eslint/js';
import globals from 'globals';
import react from 'eslint-plugin-react';
import reactHooks from 'eslint-plugin-react-hooks';

export default [
  { ignores: ['**/node_modules/**', '**/dist/**', 'backend/data/**', 'e2e/fixtures/**'] },
  js.configs.recommended,
  {
    rules: {
      'no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
    },
  },
  {
    files: ['backend/**/*.{js,mjs}', 'shared/**/*.{js,mjs}', 'scripts/**/*.mjs', 'e2e/**/*.mjs', 'extension/build.mjs', 'extension/test/**/*.js', 'frontend/vite.config.js', 'eslint.config.js'],
    languageOptions: { ecmaVersion: 2024, sourceType: 'module', globals: { ...globals.node } },
  },
  {
    files: ['extension/src/**/*.js'],
    languageOptions: { ecmaVersion: 2024, sourceType: 'module', globals: { ...globals.browser, ...globals.webextensions, __FX_API_BASE__: 'readonly', __FX_APP_URL__: 'readonly' } },
  },
  {
    files: ['frontend/src/**/*.{js,jsx}'],
    languageOptions: { ecmaVersion: 2024, sourceType: 'module', globals: { ...globals.browser }, parserOptions: { ecmaFeatures: { jsx: true } } },
    plugins: { react, 'react-hooks': reactHooks },
    settings: { react: { version: '18.3' } },
    rules: {
      ...reactHooks.configs.recommended.rules,
      'react/jsx-uses-vars': 'error',
      'react/jsx-uses-react': 'error',
      'react/jsx-no-target-blank': 'error',
      'react/no-danger': 'error',
    },
  },
];
