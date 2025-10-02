import 'package:seckit/seckit.dart';
import 'package:test/test.dart';

void main() {
  group('PasswordHasher', () {
    const hasher = PasswordHasher();

    test('should hash password correctly', () {
      const password = 'password123';
      final result = hasher.hash(password);
      expect(result.isValue, isTrue);
      expect(result.asValue!.value, isNotEmpty);
      expect(result.asValue!.value, isNot(equals(password)));
    });

    test('should produce different hashes for same password due to salt', () {
      const password = 'password123';
      final result1 = hasher.hash(password);
      final result2 = hasher.hash(password);
      expect(result1.isValue, isTrue);
      expect(result2.isValue, isTrue);
      expect(result1.asValue!.value, isNot(equals(result2.asValue!.value)));
    });

    test('should verify correct password against stored hash', () {
      const password = 'mySecretPassword';

      // Simulate registration: hash and save to DB
      final hashResult = hasher.hash(password);
      expect(hashResult.isValue, isTrue);
      final storedHash = hashResult.asValue!.value;

      // Simulate login: verify password against stored hash
      final verifyResult = hasher.verify(password, storedHash);
      expect(verifyResult.isValue, isTrue);
      expect(verifyResult.asValue!.value, isTrue);
    });

    test('should reject incorrect password', () {
      const correctPassword = 'mySecretPassword';
      const wrongPassword = 'wrongPassword';

      final hashResult = hasher.hash(correctPassword);
      final storedHash = hashResult.asValue!.value;

      final verifyResult = hasher.verify(wrongPassword, storedHash);
      expect(verifyResult.isValue, isTrue);
      expect(verifyResult.asValue!.value, isFalse);
    });

    test('should return error for empty password in verify', () {
      final verifyResult = hasher.verify('', 'some-hash');
      expect(verifyResult.isError, isTrue);
      expect(
        verifyResult.asError!.error,
        contains('[InvalidArgument] Password is empty'),
      );
    });

    test('should return error for empty hash in verify', () {
      final verifyResult = hasher.verify('password', '');
      expect(verifyResult.isError, isTrue);
      expect(
        verifyResult.asError!.error,
        contains('[InvalidArgument] Hash is empty'),
      );
    });

    test('should return error for empty password', () {
      final result = hasher.hash('');
      expect(result.isError, isTrue);
      expect(
        result.asError!.error,
        contains('[InvalidArgument] Password is empty'),
      );
    });

    test('should handle extremely long passwords', () {
      final longPassword = 'a' * 10000;
      final result = hasher.hash(longPassword);
      expect(result.isValue, isTrue);
      expect(result.asValue!.value, isNotEmpty);
    });

    test('should handle passwords with special characters', () {
      final specialPassword = '🔐!@#\$%^&*()_+-=[]{}|;:,.<>?/~`';
      final result = hasher.hash(specialPassword);
      expect(result.isValue, isTrue);

      final verifyResult =
          hasher.verify(specialPassword, result.asValue!.value);
      expect(verifyResult.isValue, isTrue);
      expect(verifyResult.asValue!.value, isTrue);
    });

    test('should handle unicode passwords correctly', () {
      const unicodePassword = 'пароль测试🔑émojï';
      final result = hasher.hash(unicodePassword);
      expect(result.isValue, isTrue);

      final verifyResult =
          hasher.verify(unicodePassword, result.asValue!.value);
      expect(verifyResult.isValue, isTrue);
      expect(verifyResult.asValue!.value, isTrue);
    });

    test('should verify invalid bcrypt hash format', () {
      const validPassword = 'test123';
      const invalidHash = 'not-a-bcrypt-hash';

      final verifyResult = hasher.verify(validPassword, invalidHash);
      expect(verifyResult.isError, isTrue);
      expect(
        verifyResult.asError!.error,
        contains('[Internal] Verification failed'),
      );
    });

    test('should handle malformed hash in verify', () {
      const validPassword = 'test123';
      const malformedHash = '\$2a\$10\$invalid';

      final verifyResult = hasher.verify(validPassword, malformedHash);
      expect(verifyResult.isError, isTrue);
    });
  });
}
