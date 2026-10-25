import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/services/session_command_approval.dart';

void main() {
  test('allows only the exact command approved in this session', () {
    final approvals = SessionCommandApproval();
    approvals.approve('nmap -sV -p 443 192.0.2.10');

    expect(approvals.isApproved('nmap -sV -p 443 192.0.2.10'), isTrue);
    expect(approvals.isApproved('nmap -sV -p 80 192.0.2.10'), isFalse);
    expect(approvals.isApproved('nmap -sV -p 443 192.0.2.11'), isFalse);
  });

  test('ignores harmless leading and trailing whitespace only', () {
    final approvals = SessionCommandApproval();
    approvals.approve('  curl -I https://example.test/  ');

    expect(approvals.isApproved('curl -I https://example.test/'), isTrue);
    expect(approvals.isApproved('curl  -I https://example.test/'), isFalse);
  });

  test('does not approve an empty command', () {
    final approvals = SessionCommandApproval();
    approvals.approve('   ');

    expect(approvals.isApproved(''), isFalse);
    expect(approvals.count, 0);
  });

  test('clear removes every session approval', () {
    final approvals = SessionCommandApproval();
    approvals.approve('command one');
    approvals.approve('command two');

    approvals.clear();

    expect(approvals.isApproved('command one'), isFalse);
    expect(approvals.isApproved('command two'), isFalse);
    expect(approvals.count, 0);
  });
}
