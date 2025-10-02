/// For security reasons, environment variables should be used to configure sensitive settings.
/// Configuration class for seckit package.
/// Contains settings for JWT secrets, database encryption, and environment flags.
class Config {
  final String secretKey;
  final String dbSecretKey;
  final String devAuthToken;
  final bool isProd;

  const Config({
    required this.secretKey,
    required this.dbSecretKey,
    required this.devAuthToken,
    required this.isProd,
  });
}
