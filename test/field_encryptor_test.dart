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
      const testValue = 'пользователь@почта.рф';

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

    test('should create identical encrypted values for the same email', () {
      const email = 'test@example.com';

      final encrypted1 = fieldEncryptor.encrypt(email).asValue!.value;
      final encrypted2 = fieldEncryptor.encrypt(email).asValue!.value;
      final encrypted3 = fieldEncryptor.encrypt(email).asValue!.value;

      expect(encrypted1, equals(encrypted2));
      expect(encrypted2, equals(encrypted3));
      expect(encrypted1, equals(encrypted3));

      final decrypted1 = fieldEncryptor.decrypt(encrypted1).asValue!.value;
      final decrypted2 = fieldEncryptor.decrypt(encrypted2).asValue!.value;
      final decrypted3 = fieldEncryptor.decrypt(encrypted3).asValue!.value;

      expect(decrypted1, equals(email));
      expect(decrypted2, equals(email));
      expect(decrypted3, equals(email));
    });

    test('should create different encrypted values for different emails', () {
      const email1 = 'user1@example.com';
      const email2 = 'user2@example.com';

      final encrypted1 = fieldEncryptor.encrypt(email1).asValue!.value;
      final encrypted2 = fieldEncryptor.encrypt(email2).asValue!.value;

      expect(encrypted1, isNot(equals(encrypted2)));

      final decrypted1 = fieldEncryptor.decrypt(encrypted1).asValue!.value;
      final decrypted2 = fieldEncryptor.decrypt(encrypted2).asValue!.value;

      expect(decrypted1, equals(email1));
      expect(decrypted2, equals(email2));
    });

    test('should work deterministically with empty strings', () {
      const emptyString = '';

      final encrypted1 = fieldEncryptor.encrypt(emptyString).asValue!.value;
      final encrypted2 = fieldEncryptor.encrypt(emptyString).asValue!.value;

      expect(encrypted1, equals(encrypted2));

      final decrypted1 = fieldEncryptor.decrypt(encrypted1).asValue!.value;
      final decrypted2 = fieldEncryptor.decrypt(encrypted2).asValue!.value;

      expect(decrypted1, equals(emptyString));
      expect(decrypted2, equals(emptyString));
    });

    test('should demonstrate solution to duplicates problem', () {
      const email = 'duplicate@example.com';

      final encryptedEmails = <String>[];

      for (int i = 0; i < 5; i++) {
        encryptedEmails.add(fieldEncryptor.encrypt(email).asValue!.value);
      }

      final firstEncrypted = encryptedEmails.first;
      for (final encrypted in encryptedEmails) {
        expect(encrypted, equals(firstEncrypted));
      }

      final newUserEncryptedEmail =
          fieldEncryptor.encrypt(email).asValue!.value;

      final hasDuplicate = encryptedEmails.contains(newUserEncryptedEmail);
      expect(hasDuplicate, isTrue);
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

      expect(adminEmail, equals(adminEmailDecoded));
      expect(user1Email, isNot(equals(user1EmailEncrypted)));
      expect(user2Email, isNot(equals(user2EmailEncrypted)));
      expect(user1EmailEncrypted, isNot(equals(user2EmailEncrypted)));
    });
  });

  group('FieldEncryptor Edge Cases', () {
    test('should return error for empty secret key', () {
      final encryptor =
          FieldEncryptor(dbSecretKey: '', salt: 'test_salt_16chars_min');
      final result = encryptor.encrypt('test');
      expect(result.isError, isTrue);
      expect(
        result.asError!.error,
        contains('[InvalidArgument] DB secret key is empty'),
      );
    });

    test('should throw for short salt in debug mode', () {
      expect(
        () => FieldEncryptor(dbSecretKey: config.dbSecretKey, salt: 'short'),
        throwsA(isA<AssertionError>()),
      );
    });

    test('should return error for invalid key length', () {
      final invalidKey = base64.encode(List<int>.generate(16, (i) => i));
      final encryptor = FieldEncryptor(
          dbSecretKey: invalidKey, salt: 'test_salt_16chars_min');
      final result = encryptor.encrypt('test');
      expect(result.isError, isTrue);
      expect(
        result.asError!.error,
        contains('[InvalidArgument] Invalid key length'),
      );
    });

    test('should return error for value exceeding max length', () {
      final longValue = 'a' * 10001;
      final result = fieldEncryptor.encrypt(longValue);
      expect(result.isError, isTrue);
      expect(
        result.asError!.error,
        contains('[InvalidArgument] Value exceeds maximum length'),
      );
    });

    test('should return error for reserved empty string marker', () {
      const emptyStringMarker = '\u0001EMPTY\u0001';
      final result = fieldEncryptor.encrypt(emptyStringMarker);
      expect(result.isError, isTrue);
      expect(
        result.asError!.error,
        contains(
            '[InvalidArgument] Value cannot be the reserved empty string marker'),
      );
    });

    test('should return error for tampered data (HMAC mismatch)', () {
      const testValue = 'test@example.com';
      final encrypted = fieldEncryptor.encrypt(testValue).asValue!.value;

      // Tamper with the encrypted data
      final encryptedBytes = base64.decode(encrypted);
      encryptedBytes[0] ^= 0xFF; // Flip bits in first byte
      final tamperedEncrypted = base64.encode(encryptedBytes);

      final result = fieldEncryptor.decrypt(tamperedEncrypted);
      expect(result.isError, isTrue);
      expect(
        result.asError!.error,
        contains('[DataLoss] Authentication failed'),
      );
    });

    test('should return error for data too short to be valid', () {
      final shortData = base64.encode(List<int>.generate(60, (i) => i));
      final result = fieldEncryptor.decrypt(shortData);
      expect(result.isError, isTrue);
      expect(
        result.asError!.error,
        contains('[InvalidArgument] Invalid encrypted data length'),
      );
    });

    test('should handle invalid base64 in decrypt', () {
      const invalidBase64 = 'not-valid-base64!@#';
      final result = fieldEncryptor.decrypt(invalidBase64);
      expect(result.isError, isTrue);
      expect(
        result.asError!.error,
        contains('[Internal] Invalid encrypted value'),
      );
    });

    test('should handle extreme edge cases in encryption', () {
      final testCases = [
        '\u0000', // null character
        '\u0001', // control character
        'a\nb\tc\rd', // mixed whitespace
        ' \t\n\r ', // only whitespace
        'привет\u00A0world', // non-breaking space
      ];

      for (final testCase in testCases) {
        final encrypted = fieldEncryptor.encrypt(testCase).asValue!.value;
        final decrypted = fieldEncryptor.decrypt(encrypted).asValue!.value;
        expect(decrypted, equals(testCase),
            reason: 'Failed for: ${testCase.codeUnits}');
      }
    });

    test('should generate different IVs for different values', () {
      const value1 = 'test1@example.com';
      const value2 = 'test2@example.com';

      final encrypted1 = fieldEncryptor.encrypt(value1).asValue!.value;
      final encrypted2 = fieldEncryptor.encrypt(value2).asValue!.value;

      // Different values should produce different encrypted results
      expect(encrypted1, isNot(equals(encrypted2)));

      // But same values should produce same results
      final encrypted1Again = fieldEncryptor.encrypt(value1).asValue!.value;
      expect(encrypted1, equals(encrypted1Again));
    });
  });
}
