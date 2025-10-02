/// Utility class for email operations.
class EmailUtils {
  /// Masks an email address for privacy, showing only the first character of the name.
  static String mask(String email) {
    final parts = email.split('@');
    if (parts.length != 2) return email;

    final name = parts[0];
    final domain = parts[1];

    if (name.length <= 2) {
      return '${name[0]}***@$domain';
    }

    return '${name.substring(0, 2)}***@$domain';
  }
}
