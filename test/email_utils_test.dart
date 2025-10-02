import 'package:seckit/seckit.dart';
import 'package:test/test.dart';

void main() {
  group('EmailUtils', () {
    group('mask', () {
      test('should mask short email correctly', () {
        const email = 'a@b.com';
        final masked = EmailUtils.mask(email);
        expect(masked, equals('a***@b.com'));
      });

      test('should mask long email correctly', () {
        const email = 'user@example.com';
        final masked = EmailUtils.mask(email);
        expect(masked, equals('us***@example.com'));
      });

      test('should return original email if too short', () {
        const email = 'u@v.w';
        final masked = EmailUtils.mask(email);
        expect(masked, equals('u***@v.w'));
      });

      test('should mask 2-character username correctly', () {
        const email = 'ab@domain.com';
        final masked = EmailUtils.mask(email);
        expect(masked, equals('a***@domain.com'));
      });

      test('should mask 3-character username correctly', () {
        const email = 'abc@domain.com';
        final masked = EmailUtils.mask(email);
        expect(masked, equals('ab***@domain.com'));
      });

      test('should handle email without @ symbol', () {
        const email = 'notanemail';
        final masked = EmailUtils.mask(email);
        expect(masked, equals('notanemail'));
      });

      test('should handle email with multiple @ symbols', () {
        const email = 'user@domain@example.com';
        final masked = EmailUtils.mask(email);
        expect(masked, equals('user@domain@example.com'));
      });

      test('should handle empty string', () {
        const email = '';
        final masked = EmailUtils.mask(email);
        expect(masked, equals(''));
      });

      test('should handle very long username', () {
        const email = 'verylongusername123456@example.com';
        final masked = EmailUtils.mask(email);
        expect(masked, equals('ve***@example.com'));
      });

      test('should handle unicode characters', () {
        const email = 'пользователь@домен.рф';
        final masked = EmailUtils.mask(email);
        expect(masked, equals('по***@домен.рф'));
      });

      test('should handle email with special characters', () {
        const email = 'user+tag@example.com';
        final masked = EmailUtils.mask(email);
        expect(masked, equals('us***@example.com'));
      });

      test('should handle subdomain emails', () {
        const email = 'user@mail.example.com';
        final masked = EmailUtils.mask(email);
        expect(masked, equals('us***@mail.example.com'));
      });

      test('should handle edge case with single character before @', () {
        const email = 'x@domain.com';
        final masked = EmailUtils.mask(email);
        expect(masked, equals('x***@domain.com'));
      });

      test('should handle emails with dots in domain', () {
        const email = 'user@sub.domain.co.uk';
        final masked = EmailUtils.mask(email);
        expect(masked, equals('us***@sub.domain.co.uk'));
      });

      test('should handle emails with numbers', () {
        const email = 'user123@example.com';
        final masked = EmailUtils.mask(email);
        expect(masked, equals('us***@example.com'));
      });

      test('should be consistent with same input', () {
        const email = 'test@example.com';
        final masked1 = EmailUtils.mask(email);
        final masked2 = EmailUtils.mask(email);
        expect(masked1, equals(masked2));
      });
    });
  });
}
