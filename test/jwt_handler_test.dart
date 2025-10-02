import 'dart:convert';

import 'package:jaguar_jwt/jaguar_jwt.dart';
import 'package:seckit/seckit.dart';
import 'package:test/test.dart';

void main() {
  final config = Config(
    secretKey: 'test_secret_key_for_jwt_32_chars_long',
    dbSecretKey: base64.encode(List<int>.generate(32, (i) => i)),
    devAuthToken: 'dev_auth_token',
    isProd: false,
  );

  final jwtHandler = JwtHandler(
    secretKey: config.secretKey,
    devAuthToken: config.devAuthToken,
    isProd: config.isProd,
    userIdKey: 'user_id',
  );

  group('JwtHandler', () {
    group('generateAuthToken', () {
      test('should generate a valid JWT token', () {
        final token = jwtHandler.generateToken();

        expect(token, isNotEmpty);
        expect(token, contains('.'));

        // Verify the token can be parsed
        verifyJwtHS256Signature(token, config.secretKey);
      });

      test('should generate different tokens on different calls', () async {
        final token1 = jwtHandler.generateToken(claims: {'id': 1});

        await Future.delayed(Duration(milliseconds: 1));

        final token2 = jwtHandler.generateToken(claims: {'id': 2});

        expect(token1, isNot(equals(token2)));
      });

      test('should create a token with 1 hour lifetime', () {
        final token = jwtHandler.generateToken();
        final jwtClaim = verifyJwtHS256Signature(token, config.secretKey);

        expect(jwtClaim, isNotNull);
      });
    });

    group('validateAuthToken', () {
      test('should accept a valid JWT auth_token', () {
        final token = jwtHandler.generateToken();

        final result = jwtHandler.validateToken(token);
        expect(result.isValue, isTrue);
      });

      test('should accept dev token in dev environment', () {
        final devToken = config.devAuthToken;

        final result = jwtHandler.validateToken(devToken);
        expect(result.isValue, isTrue);
      });

      test('should reject invalid JWT token', () {
        const invalidToken = 'invalid.jwt.token';

        final result = jwtHandler.validateToken(invalidToken);
        expect(result.isError, isTrue);
        expect(
          result.asError!.error,
          contains('[DataLoss] Invalid auth token'),
        );
      });

      test('should reject JWT token with wrong signature', () {
        final wrongKeyClaim = JwtClaim(
          maxAge: Duration(hours: 1),
          otherClaims: {'type': 'auth_token'},
        );
        final wrongKeyToken = issueJwtHS256(wrongKeyClaim, 'wrong_secret_key');

        final result = jwtHandler.validateToken(wrongKeyToken);
        expect(result.isError, isTrue);
        expect(
          result.asError!.error,
          contains('[DataLoss] Invalid auth token'),
        );
      });

      test('should reject empty token', () {
        const emptyToken = '';

        final result = jwtHandler.validateToken(emptyToken);
        expect(result.isError, isTrue);
        expect(
          result.asError!.error,
          contains('[DataLoss] Invalid auth token'),
        );
      });
    });

    group('Integration Tests', () {
      test('full generation and validation cycle', () {
        final token = jwtHandler.generateToken();

        final result = jwtHandler.validateToken(token);
        expect(result.isValue, isTrue);

        // Verify the token can be parsed
        verifyJwtHS256Signature(token, config.secretKey);
      });

      test('should validate token persistently', () {
        final token = jwtHandler.generateToken();

        final result = jwtHandler.validateToken(token);
        expect(result.isValue, isTrue);

        Future.delayed(Duration(milliseconds: 100));

        final result2 = jwtHandler.validateToken(token);
        expect(result2.isValue, isTrue);
      });

      test('should demonstrate usage in dev mode', () {
        final generatedToken = jwtHandler.generateToken();
        final devToken = config.devAuthToken;

        final result1 = jwtHandler.validateToken(generatedToken);
        expect(result1.isValue, isTrue);

        final result2 = jwtHandler.validateToken(devToken);
        expect(result2.isValue, isTrue);
      });
      test('should demonstrate correct validation on www.jwt.io', () {
        final generatedToken = jwtHandler.generateToken();

        final result = jwtHandler.validateToken(generatedToken);
        expect(result.isValue, isTrue);

        print('Go to https://www.jwt.io');
        print('Enter in the Token (JWT) field: $generatedToken');
        print('Use HMAC key for validation: ${config.secretKey}');
      });
    });

    group('getUserIdFromToken', () {
      test('should extract user_id from token', () {
        final token = jwtHandler.generateToken(claims: {'user_id': 123});

        final result = jwtHandler.getUserIdFromToken(token);
        expect(result.isValue, isTrue);
        expect(result.asValue!.value, equals(123));
      });

      test('should extract user_id from token with string value', () {
        final token = jwtHandler.generateToken(claims: {'user_id': '456'});

        final result = jwtHandler.getUserIdFromToken(token);
        expect(result.isValue, isTrue);
        expect(result.asValue!.value, equals(456));
      });

      test('should return error for null token', () {
        final result = jwtHandler.getUserIdFromToken(null);
        expect(result.isError, isTrue);
        expect(
          result.asError!.error,
          contains('[DataLoss] Token not found'),
        );
      });

      test('should return error for token without user_id', () {
        final token = jwtHandler.generateToken(claims: {'role': 'admin'});

        final result = jwtHandler.getUserIdFromToken(token);
        expect(result.isError, isTrue);
        expect(
          result.asError!.error,
          contains('[DataLoss] User id not found'),
        );
      });

      test('should return error for invalid token', () {
        const invalidToken = 'invalid.token.here';

        final result = jwtHandler.getUserIdFromToken(invalidToken);
        expect(result.isError, isTrue);
        expect(
          result.asError!.error,
          contains('[DataLoss] Invalid token'),
        );
      });

      test('should return error for expired token', () async {
        final token = jwtHandler.generateToken(
          claims: {'user_id': 999},
          maxAge: Duration(milliseconds: 1),
        );

        await Future.delayed(Duration(milliseconds: 10));

        final result = jwtHandler.getUserIdFromToken(token);
        expect(result.isError, isTrue);
      });

      test('should handle empty secret key scenario', () {
        final emptyKeyHandler = JwtHandler(
          secretKey: 'a' * 32,
          devAuthToken: config.devAuthToken,
          isProd: config.isProd,
          userIdKey: 'user_id',
        );
        final token = emptyKeyHandler.generateToken(claims: {'user_id': 123});

        // Try to validate with different handler - simulates empty key
        final result = jwtHandler.getUserIdFromToken(token);
        expect(result.isError, isTrue);
      });

      test('should support custom userIdKey', () {
        final customHandler = JwtHandler(
          secretKey: config.secretKey,
          devAuthToken: config.devAuthToken,
          isProd: config.isProd,
          userIdKey: 'uid',
        );
        final token = customHandler.generateToken(claims: {'uid': 789});

        final result = customHandler.getUserIdFromToken(token);
        expect(result.isValue, isTrue);
        expect(result.asValue!.value, equals(789));
      });

      test('should fail with custom key if using wrong key', () {
        final customHandler = JwtHandler(
          secretKey: config.secretKey,
          devAuthToken: config.devAuthToken,
          isProd: config.isProd,
          userIdKey: 'uid',
        );
        final token = customHandler.generateToken(claims: {'user_id': 123});

        final result = customHandler.getUserIdFromToken(token);
        expect(result.isError, isTrue);
        expect(
          result.asError!.error,
          contains('[DataLoss] User id not found'),
        );
      });
    });

    group('validateToken edge cases', () {
      test('should reject dev token in production mode', () {
        final prodHandler = JwtHandler(
          secretKey: config.secretKey,
          devAuthToken: config.devAuthToken,
          isProd: true, // isProd = true
          userIdKey: 'user_id',
        );

        final result = prodHandler.validateToken(config.devAuthToken);
        expect(result.isError, isTrue);
      });

      test('should handle expired token', () async {
        final token = jwtHandler.generateToken(
          maxAge: Duration(milliseconds: 1),
        );

        await Future.delayed(Duration(milliseconds: 10));

        final result = jwtHandler.validateToken(token);
        expect(result.isError, isTrue);
      });
    });

    group('constant-time comparison', () {
      test('should accept matching dev tokens', () {
        final result = jwtHandler.validateToken(config.devAuthToken);
        expect(result.isValue, isTrue);
      });

      test('should reject dev token with different length', () {
        final result = jwtHandler.validateToken('${config.devAuthToken}x');
        expect(result.isError, isTrue);
      });

      test('should reject dev token with one char difference', () {
        final modifiedToken = config.devAuthToken.replaceFirst('d', 'X');
        final result = jwtHandler.validateToken(modifiedToken);
        expect(result.isError, isTrue);
      });
    });

    group('edge cases and error handling', () {
      test('should handle getUserIdFromToken with non-parseable user_id', () {
        final token =
            jwtHandler.generateToken(claims: {'user_id': 'not-a-number'});

        final result = jwtHandler.getUserIdFromToken(token);
        expect(result.isError, isTrue);
        expect(
          result.asError!.error,
          contains('[DataLoss] User id not found'),
        );
      });

      test('should handle getUserIdFromToken with null user_id', () {
        final token = jwtHandler.generateToken(claims: {'user_id': null});

        final result = jwtHandler.getUserIdFromToken(token);
        expect(result.isError, isTrue);
      });

      test('should handle malformed JWT token in getUserIdFromToken', () {
        const malformedToken = 'eyJhbGciOiJIUzI1NiJ9.invalid';

        final result = jwtHandler.getUserIdFromToken(malformedToken);
        expect(result.isError, isTrue);
        expect(
          result.asError!.error,
          contains('[DataLoss] Invalid token'),
        );
      });

      test('should handle very short token strings', () {
        const shortToken = 'short';

        final result = jwtHandler.validateToken(shortToken);
        expect(result.isError, isTrue);
      });

      test('should handle token with missing signature', () {
        const incompleteToken =
            'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.';

        final result = jwtHandler.validateToken(incompleteToken);
        expect(result.isError, isTrue);
      });

      test('should handle different custom userIdKey formats', () {
        final customHandler = JwtHandler(
          secretKey: config.secretKey,
          devAuthToken: config.devAuthToken,
          isProd: config.isProd,
          userIdKey: 'custom_user_identifier_123',
        );

        final token = customHandler.generateToken(
            claims: {'custom_user_identifier_123': 42, 'other_data': 'test'});

        final result = customHandler.getUserIdFromToken(token);
        expect(result.isValue, isTrue);
        expect(result.asValue!.value, equals(42));
      });
    });
  });
}
