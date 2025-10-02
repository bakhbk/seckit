import 'dart:convert';
import 'dart:typed_data';

import 'package:async_lite/async_lite.dart';
import 'package:crypto/crypto.dart';
import 'package:encrypt/encrypt.dart';

/// Provides deterministic AES encryption for database fields.
/// Useful for encrypting sensitive data while maintaining searchability.
///
/// ⚠️ SECURITY NOTE: Uses deterministic IV for searchability.
/// This means identical plaintexts produce identical ciphertexts.
/// Trade-off: searchability vs perfect forward secrecy.
class FieldEncryptor {
  final String dbSecretKey;
  final String salt;

  /// Creates a FieldEncryptor.
  /// [dbSecretKey] must be base64-encoded 32-byte key.
  /// [salt] should be unique per application/environment.
  FieldEncryptor({
    required this.dbSecretKey,
    required this.salt,
  }) : assert(
          salt.length >= 16,
          'salt must be at least 16 characters for security. '
          'Current length: ${salt.length}',
        );

  /// Encrypts a string value using deterministic AES encryption.
  Result<String> encrypt(String value) {
    return _encryptField(value, isDecode: false);
  }

  /// Decrypts an encrypted string value.
  Result<String> decrypt(String encryptedValue) {
    return _encryptField(encryptedValue, isDecode: true);
  }

  Result<String> _encryptField(String value, {required bool isDecode}) {
    try {
      if (dbSecretKey.isEmpty) {
        return Result.error('[InvalidArgument] DB secret key is empty');
      }

      // Prevent DoS attacks via extremely long inputs
      if (!isDecode && value.length > 10000) {
        return Result.error(
          '[InvalidArgument] Value exceeds maximum length of 10000 characters',
        );
      }

      final keyBytes = base64.decode(dbSecretKey);
      if (keyBytes.length != 32) {
        return Result.error(
          '[InvalidArgument] Invalid key length: ${keyBytes.length} bytes. Expected 32 bytes',
        );
      }

      final key = Key(keyBytes);
      final encryptor = Encrypter(
        AES(key, mode: AESMode.cbc, padding: 'PKCS7'),
      );

      const emptyStringMarker = '\u0001EMPTY\u0001';

      if (isDecode) {
        final encryptedBytes = base64.decode(value);

        // Minimum length: 16 (IV) + 16 (one AES block) + 32 (HMAC-SHA256)
        if (encryptedBytes.length < 64) {
          return Result.error(
              '[InvalidArgument] Invalid encrypted data length');
        }

        // Extract and verify HMAC (last 32 bytes)
        final receivedMac = encryptedBytes.sublist(encryptedBytes.length - 32);
        final dataToVerify =
            encryptedBytes.sublist(0, encryptedBytes.length - 32);

        final hmac = Hmac(sha256, keyBytes);
        final computedMac = hmac.convert(dataToVerify);

        // Constant-time comparison to prevent timing attacks
        var macResult = receivedMac.length ^ computedMac.bytes.length;
        final macMinLength = receivedMac.length < computedMac.bytes.length
            ? receivedMac.length
            : computedMac.bytes.length;
        for (var i = 0; i < macMinLength; i++) {
          macResult |= receivedMac[i] ^ computedMac.bytes[i];
        }

        if (macResult != 0) {
          return Result.error(
            '[DataLoss] Authentication failed - data may have been tampered with',
          );
        }

        final ivBytes = dataToVerify.sublist(0, 16);
        final iv = IV(Uint8List.fromList(ivBytes));

        final encryptedData = dataToVerify.sublist(16);
        final encrypted = Encrypted(Uint8List.fromList(encryptedData));

        final decrypted = encryptor.decrypt(encrypted, iv: iv);

        if (decrypted == emptyStringMarker) {
          return Result.value('');
        }

        return Result.value(decrypted);
      } else {
        // Prevent bypass attack using the empty string marker
        if (value == emptyStringMarker) {
          return Result.error(
            '[InvalidArgument] Value cannot be the reserved empty string marker',
          );
        }

        final valueToEncrypt = value.isEmpty ? emptyStringMarker : value;

        final iv = _generateDeterministicIV(valueToEncrypt);
        final encrypted = encryptor.encrypt(valueToEncrypt, iv: iv);

        final combinedBytes = <int>[];
        combinedBytes.addAll(iv.bytes);
        combinedBytes.addAll(encrypted.bytes);

        // Add HMAC for authentication (encrypt-then-MAC)
        final hmac = Hmac(sha256, keyBytes);
        final mac = hmac.convert(combinedBytes);
        combinedBytes.addAll(mac.bytes);

        return Result.value(base64.encode(combinedBytes));
      }
    } catch (e) {
      // Note: Stack trace omitted from error message for security.
      // Log full error internally if needed: logger.error('Encryption failed', error: e);
      return Result.error('[Internal] Invalid encrypted value $e');
    }
  }

  /// Generates a deterministic IV based on the value and secret key.
  /// Uses HMAC to include the secret key, preventing IV prediction attacks.
  IV _generateDeterministicIV(String value) {
    // Use HMAC-SHA256 with secret key to prevent IV prediction
    final keyBytes = base64.decode(dbSecretKey);
    final hmac = Hmac(sha256, keyBytes);
    final bytes = utf8.encode('$value|$salt');
    final hash = hmac.convert(bytes);

    final ivBytes = hash.bytes.take(16).toList();
    return IV(Uint8List.fromList(ivBytes));
  }
}
