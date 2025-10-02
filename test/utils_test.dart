import 'dart:convert';

import 'package:seckit/seckit.dart';
import 'package:test/test.dart';

void main() {
  final config = Config(
    secretKey: 'test_secret_key_for_jwt_32_chars_long',
    dbSecretKey: base64.encode(List<int>.generate(32, (i) => i)),
    devAuthToken: 'dev_auth_token',
    isProd: false,
  );

  final fieldEncryptor = FieldEncryptor(
      dbSecretKey: config.dbSecretKey, salt: 'test_salt_16chars_min');

  group('FieldEncryptor', () {
    test('should correctly encrypt and decrypt a string', () {
      const testValue = 'test@example.com';

      final encryptResult = fieldEncryptor.encrypt(testValue);
      final encrypted = encryptResult.asValue!.value;

      final decryptResult = fieldEncryptor.decrypt(encrypted);
      final decrypted = decryptResult.asValue!.value;

      expect(decrypted, equals(testValue));
      expect(encrypted, isNot(equals(testValue)));
      expect(encrypted.length, greaterThan(testValue.length));
    });

    test('should generate identical encrypted values for identical text', () {
      const testValue = 'same@email.com';

      final encrypted1 = fieldEncryptor.encrypt(testValue).asValue!.value;
      final encrypted2 = fieldEncryptor.encrypt(testValue).asValue!.value;

      expect(encrypted1, equals(encrypted2));

      final decrypted1 = fieldEncryptor.decrypt(encrypted1).asValue!.value;
      final decrypted2 = fieldEncryptor.decrypt(encrypted2).asValue!.value;

      expect(decrypted1, equals(testValue));
      expect(decrypted2, equals(testValue));
    });

    test('should work correctly with empty string', () {
      const testValue = '';

      final encrypted = fieldEncryptor.encrypt(testValue).asValue!.value;
      final decrypted = fieldEncryptor.decrypt(encrypted).asValue!.value;

      expect(decrypted, equals(testValue));
    });

    test('should work correctly with long strings', () {
      final testValue = 'very.long.email.address.for.testing@example.com' * 10;

      final encrypted = fieldEncryptor.encrypt(testValue).asValue!.value;
      final decrypted = fieldEncryptor.decrypt(encrypted).asValue!.value;

      expect(decrypted, equals(testValue));
    });

    test('should work correctly with Unicode characters', () {
      const testValue = 'пользователь@пример.ру';

      final encrypted = fieldEncryptor.encrypt(testValue).asValue!.value;
      final decrypted = fieldEncryptor.decrypt(encrypted).asValue!.value;

      expect(decrypted, equals(testValue));
    });

    test('should contain correct structure of encrypted data', () {
      const testValue = 'test@example.com';

      final encrypted = fieldEncryptor.encrypt(testValue).asValue!.value;
      final encryptedBytes = base64.decode(encrypted);

      expect(encryptedBytes.length, greaterThanOrEqualTo(16));
      expect(encryptedBytes.length % 16, equals(0));

      final encrypted2 = fieldEncryptor.encrypt(testValue).asValue!.value;
      expect(encrypted, equals(encrypted2));
    });

    test('should throw exception for invalid encrypted data', () {
      const invalidEncrypted = 'invalid_base64_data';

      final result = fieldEncryptor.decrypt(invalidEncrypted);

      expect(result.isError, isTrue);
    });

    test('should throw exception for data that is too short', () {
      final shortData = base64.encode([1, 2, 3]);

      final result = fieldEncryptor.decrypt(shortData);

      expect(result.isError, isTrue);
    });
  });

  group('Integration Tests', () {
    test('should work with real email addresses', () {
      final emails = [
        'user@example.com',
        'test.email+tag@domain.co.uk',
        'user123@subdomain.example.org',
        'пользователь@домен.рф',
      ];

      for (final email in emails) {
        final encrypted = fieldEncryptor.encrypt(email).asValue!.value;
        final decrypted = fieldEncryptor.decrypt(encrypted).asValue!.value;

        expect(decrypted, equals(email), reason: 'Failed for email: $email');
      }
    });

    test('should ensure consistency in multiple operations', () {
      const testValue = 'consistency.test@example.com';
      const iterations = 100;

      for (int i = 0; i < iterations; i++) {
        final encrypted = fieldEncryptor.encrypt(testValue).asValue!.value;
        final decrypted = fieldEncryptor.decrypt(encrypted).asValue!.value;

        expect(decrypted, equals(testValue), reason: 'Failed at iteration $i');
      }
    });

    test('should generate base64 compatible strings', () {
      final testValues = [
        'simple@test.com',
        'complex.email+with-symbols@sub.domain.co.uk',
        'unicode@тест.рф',
      ];

      for (final value in testValues) {
        final encrypted = fieldEncryptor.encrypt(value).asValue!.value;

        expect(() => base64.decode(encrypted), returnsNormally);

        final decrypted = fieldEncryptor.decrypt(encrypted).asValue!.value;
        expect(decrypted, equals(value));
      }
    });

    test('should handle edge cases', () {
      final testCases = [
        '', // empty string
        'a', // one character
        'ab', // two characters
        'a' * 1000, // very long string
        '🚀🔐💻', // emojis
        '\n\t\r', // control characters
      ];

      for (final testCase in testCases) {
        final encrypted = fieldEncryptor.encrypt(testCase).asValue!.value;
        final decrypted = fieldEncryptor.decrypt(encrypted).asValue!.value;

        expect(
          decrypted,
          equals(testCase),
          reason: 'Failed for test case: "$testCase"',
        );
      }
    });

    test('for demo data', () {
      const adminEmail = 'admin@example.local';
      const user1Email = 'user1@example.local';
      const user2Email = 'user2@example.local';

      final adminEncrypted = fieldEncryptor.encrypt(adminEmail).asValue!.value;
      final adminEmailDecoded =
          fieldEncryptor.decrypt(adminEncrypted).asValue!.value;
      final user1EmailEncrypted =
          fieldEncryptor.encrypt(user1Email).asValue!.value;
      final user2EmailEncrypted =
          fieldEncryptor.encrypt(user2Email).asValue!.value;

      print(
        "admin: $adminEmail - $adminEncrypted,\n"
        "user1: $user1Email - $user1EmailEncrypted,\n"
        "user2: $user2Email - $user2EmailEncrypted,\n",
      );

      expect(adminEmail, equals(adminEmailDecoded));
      expect(user1Email, isNot(equals(user1EmailEncrypted)));
      expect(user2Email, isNot(equals(user2EmailEncrypted)));
      expect(user1EmailEncrypted, isNot(equals(user2EmailEncrypted)));
    });
  });
}
