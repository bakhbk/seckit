import 'package:async_lite/async_lite.dart';
import 'package:jaguar_jwt/jaguar_jwt.dart';

/// Handles JWT token generation and validation.
/// Supports both production JWT tokens and development auth tokens.
class JwtHandler {
  final String secretKey;
  final String devAuthToken;
  final bool isProd;
  final String userIdKey;

  /// Creates a JwtHandler instance.
  /// [secretKey] must be at least 32 characters for security.
  /// [userIdKey] specifies the claim key for user ID.
  const JwtHandler({
    required this.secretKey,
    required this.devAuthToken,
    required this.isProd,
    required this.userIdKey,
  }) : assert(
          secretKey.length >= 32,
          'secretKey must be at least 32 characters for security. '
          'Current length: ${secretKey.length}',
        );

  /// Generates a JWT auth token with 1 hour expiration.
  /// Accepts custom claims.
  String generateToken({
    Map<String, dynamic> claims = const {},
    Duration maxAge = const Duration(hours: 1),
  }) {
    final claim = JwtClaim(maxAge: maxAge, otherClaims: claims);
    return issueJwtHS256(claim, secretKey);
  }

  /// Validates a JWT auth token.
  /// Returns Result\<void> - success if valid, error if invalid.
  Result<void> validateToken(String authToken) {
    if (authToken.isEmpty) {
      return Result.error('[DataLoss] Invalid auth token');
    }

    if (!isProd && _constantTimeCompare(authToken, devAuthToken)) {
      return Result.value(null);
    }
    try {
      if (secretKey.isEmpty) {
        return Result.error('[Internal] Server secret key is not set');
      }

      final claim = verifyJwtHS256Signature(authToken, secretKey);

      claim.validate();

      return Result.value(null);
    } catch (e) {
      return Result.error('[DataLoss] Invalid auth token');
    }
  }

  /// Extracts user ID from a JWT token.
  /// Returns Result\<int> with user ID or error.
  Result<int> getUserIdFromToken(String? token) {
    if (token == null) {
      return Result.error('[DataLoss] Token not found');
    }
    if (secretKey.isEmpty) {
      return Result.error('[Internal] Server secret key is not set');
    }

    try {
      final jwtClaim = verifyJwtHS256Signature(token, secretKey);
      // Validate expiration and other claims
      jwtClaim.validate();

      var id = jwtClaim[userIdKey];
      id = id is int ? id : int.tryParse(id.toString());
      if (id == null) {
        return Result.error('[DataLoss] User id not found');
      }

      return Result.value(id);
    } catch (e) {
      return Result.error('[DataLoss] Invalid token $e');
    }
  }

  /// Constant-time string comparison to prevent timing attacks.
  /// Returns true if strings are equal, false otherwise.
  /// Note: Length difference is included in constant-time comparison.
  bool _constantTimeCompare(String a, String b) {
    // Include length difference in result to prevent length-based timing attacks
    var result = a.length ^ b.length;
    final minLength = a.length < b.length ? a.length : b.length;

    for (var i = 0; i < minLength; i++) {
      result |= a.codeUnitAt(i) ^ b.codeUnitAt(i);
    }

    return result == 0;
  }
}
