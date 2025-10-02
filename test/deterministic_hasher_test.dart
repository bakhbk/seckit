import 'package:seckit/seckit.dart';
import 'package:test/test.dart';

void main() {
  group('DeterministicHasher', () {
    const secretKey = 'test-secret-key-must-be-32-chars!';
    const salt = 'test-salt-16chars';
    final hasher = DeterministicHasher(secretKey: secretKey, salt: salt);

    group('hash', () {
      test('should produce deterministic hash for same input', () {
        const value = 'test@example.com';

        final result1 = hasher.hash(value);
        final result2 = hasher.hash(value);

        expect(result1.isValue, isTrue);
        expect(result2.isValue, isTrue);
        expect(result1.asValue!.value, equals(result2.asValue!.value));
      });

      test('should produce different hashes for different inputs', () {
        const value1 = 'test1@example.com';
        const value2 = 'test2@example.com';

        final result1 = hasher.hash(value1);
        final result2 = hasher.hash(value2);

        expect(result1.isValue, isTrue);
        expect(result2.isValue, isTrue);
        expect(result1.asValue!.value, isNot(equals(result2.asValue!.value)));
      });

      test('should produce base64-encoded hash', () {
        const value = 'test@example.com';

        final result = hasher.hash(value);

        expect(result.isValue, isTrue);
        final hash = result.asValue!.value;
        expect(hash, isNotEmpty);
        // Base64 regex pattern
        expect(hash, matches(RegExp(r'^[A-Za-z0-9+/]+=*$')));
      });

      test('should produce different hashes with different salts', () {
        const value = 'test@example.com';
        final hasher1 = DeterministicHasher(
            secretKey: secretKey, salt: 'salt1-16chars-min');
        final hasher2 = DeterministicHasher(
            secretKey: secretKey, salt: 'salt2-16chars-min');

        final result1 = hasher1.hash(value);
        final result2 = hasher2.hash(value);

        expect(result1.isValue, isTrue);
        expect(result2.isValue, isTrue);
        expect(result1.asValue!.value, isNot(equals(result2.asValue!.value)));
      });

      test('should produce different hashes with different secret keys', () {
        const value = 'test@example.com';
        final hasher1 = DeterministicHasher(
            secretKey: 'key1-must-be-32-characters-long!', salt: salt);
        final hasher2 = DeterministicHasher(
            secretKey: 'key2-must-be-32-characters-long!', salt: salt);

        final result1 = hasher1.hash(value);
        final result2 = hasher2.hash(value);

        expect(result1.isValue, isTrue);
        expect(result2.isValue, isTrue);
        expect(result1.asValue!.value, isNot(equals(result2.asValue!.value)));
      });

      test('should return error for empty value', () {
        final result = hasher.hash('');

        expect(result.isError, isTrue);
        expect(
          result.asError!.error,
          contains('[InvalidArgument] Value is empty'),
        );
      });

      test('should validate secret key length in debug mode', () {
        // In debug mode, assert should throw AssertionError
        expect(
          () => DeterministicHasher(secretKey: 'short', salt: salt),
          throwsA(isA<AssertionError>()),
        );
      });

      test('should validate salt length in debug mode', () {
        expect(
          () => DeterministicHasher(secretKey: secretKey, salt: 'short'),
          throwsA(isA<AssertionError>()),
        );
      });
      test('should handle unicode characters', () {
        const value = 'тест@example.com';

        final result1 = hasher.hash(value);
        final result2 = hasher.hash(value);

        expect(result1.isValue, isTrue);
        expect(result2.isValue, isTrue);
        expect(result1.asValue!.value, equals(result2.asValue!.value));
      });

      test('should handle special characters', () {
        const value = 'test+tag@example.com';

        final result1 = hasher.hash(value);
        final result2 = hasher.hash(value);

        expect(result1.isValue, isTrue);
        expect(result2.isValue, isTrue);
        expect(result1.asValue!.value, equals(result2.asValue!.value));
      });

      test('should handle long strings', () {
        final value = 'a' * 10000;

        final result1 = hasher.hash(value);
        final result2 = hasher.hash(value);

        expect(result1.isValue, isTrue);
        expect(result2.isValue, isTrue);
        expect(result1.asValue!.value, equals(result2.asValue!.value));
      });
    });

    group('verify', () {
      test('should verify correct value against hash', () {
        const value = 'test@example.com';

        final hashResult = hasher.hash(value);
        expect(hashResult.isValue, isTrue);

        final verifyResult = hasher.verify(value, hashResult.asValue!.value);
        expect(verifyResult.isValue, isTrue);
        expect(verifyResult.asValue!.value, isTrue);
      });

      test('should reject incorrect value', () {
        const correctValue = 'test@example.com';
        const wrongValue = 'wrong@example.com';

        final hashResult = hasher.hash(correctValue);
        expect(hashResult.isValue, isTrue);

        final verifyResult = hasher.verify(
          wrongValue,
          hashResult.asValue!.value,
        );
        expect(verifyResult.isValue, isTrue);
        expect(verifyResult.asValue!.value, isFalse);
      });

      test('should return error for empty value in verify', () {
        final verifyResult = hasher.verify('', 'some-hash');

        expect(verifyResult.isError, isTrue);
        expect(
          verifyResult.asError!.error,
          contains('[InvalidArgument] Value is empty'),
        );
      });
    });

    group('Integration Tests', () {
      test('should demonstrate database lookup use case', () {
        // Simulate user registration
        const userEmail = 'user@example.com';
        final hashResult = hasher.hash(userEmail);
        expect(hashResult.isValue, isTrue);
        final storedHash = hashResult.asValue!.value;

        // Simulate database lookup by hashed email
        const searchEmail = 'user@example.com';
        final searchHashResult = hasher.hash(searchEmail);
        expect(searchHashResult.isValue, isTrue);
        final searchHash = searchHashResult.asValue!.value;

        // Should find the user (hashes match)
        expect(searchHash, equals(storedHash));

        // Try with wrong email
        const wrongEmail = 'other@example.com';
        final wrongHashResult = hasher.hash(wrongEmail);
        expect(wrongHashResult.isValue, isTrue);

        // Should not find the user (hashes don't match)
        expect(wrongHashResult.asValue!.value, isNot(equals(storedHash)));
      });

      test('should demonstrate multiple users with same domain', () {
        const email1 = 'user1@example.com';
        const email2 = 'user2@example.com';
        const email3 = 'user1@example.com'; // Same as email1

        final hash1 = hasher.hash(email1).asValue!.value;
        final hash2 = hasher.hash(email2).asValue!.value;
        final hash3 = hasher.hash(email3).asValue!.value;

        // Same email -> same hash
        expect(hash1, equals(hash3));

        // Different emails -> different hashes
        expect(hash1, isNot(equals(hash2)));
        expect(hash2, isNot(equals(hash3)));
      });
    });

    group('Edge Cases', () {
      test('should return error for value exceeding max length', () {
        final longValue = 'a' * 10001;
        final result = hasher.hash(longValue);
        expect(result.isError, isTrue);
        expect(
          result.asError!.error,
          contains('[InvalidArgument] Value exceeds maximum length'),
        );
      });

      test('should work with minimum valid secret key length', () {
        final hasherMinKey = DeterministicHasher(
          secretKey: 'a' * 32,
          salt: salt,
        );
        final result = hasherMinKey.hash('test');
        expect(result.isValue, isTrue);
        expect(result.asValue!.value, isNotEmpty);
      });

      test('should handle constant-time comparison in verify', () {
        const value = 'test@example.com';
        final hashResult = hasher.hash(value);
        final hash = hashResult.asValue!.value;

        // Test with correct value
        final verifyCorrect = hasher.verify(value, hash);
        expect(verifyCorrect.asValue!.value, isTrue);

        // Test with different length hash
        final verifyDifferentLength = hasher.verify(value, '${hash}x');
        expect(verifyDifferentLength.asValue!.value, isFalse);

        // Test with same length but different content
        final modifiedHash = '${hash.substring(0, hash.length - 1)}X';
        final verifyModified = hasher.verify(value, modifiedHash);
        expect(verifyModified.asValue!.value, isFalse);
      });

      test('verify should propagate hash errors', () {
        final result = hasher.verify('', 'some-hash');
        expect(result.isError, isTrue);
        expect(
          result.asError!.error,
          contains('[InvalidArgument] Value is empty'),
        );
      });

      test('should test internal validation coverage', () {
        // Test that the hash method works correctly with valid inputs
        // This covers the success path and internal validations
        final result = hasher.hash('test-value');
        expect(result.isValue, isTrue);
        expect(result.asValue!.value, isNotEmpty);
      });

      test('should handle edge case with exactly 10000 characters', () {
        final maxLengthValue = 'a' * 10000;
        final result = hasher.hash(maxLengthValue);
        expect(result.isValue, isTrue);
      });

      test('should handle various input sizes efficiently', () {
        final testSizes = [1, 10, 100, 1000, 5000, 9999];

        for (final size in testSizes) {
          final testValue = 'x' * size;
          final result = hasher.hash(testValue);
          expect(result.isValue, isTrue, reason: 'Failed for size $size');
        }
      });
    });
  });
}
