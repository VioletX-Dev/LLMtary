import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/digests/sha256.dart';

/// Ephemeral operator approvals for one active assessment session.
///
/// Only leading and trailing whitespace is normalized. Arguments, targets,
/// quoting, operators, and internal whitespace remain identity-significant.
/// Raw commands are never retained in the approval set.
class SessionCommandApproval {
  final Set<String> _approvedDigests = <String>{};

  void approve(String command) {
    final identity = _identity(command);
    if (identity != null) _approvedDigests.add(identity);
  }

  bool isApproved(String command) {
    final identity = _identity(command);
    return identity != null && _approvedDigests.contains(identity);
  }

  void clear() => _approvedDigests.clear();

  int get count => _approvedDigests.length;

  static String? _identity(String command) {
    final normalized = command.trim();
    if (normalized.isEmpty) return null;
    final bytes = Uint8List.fromList(utf8.encode(normalized));
    final digest = SHA256Digest().process(bytes);
    return base64Url.encode(digest);
  }
}
