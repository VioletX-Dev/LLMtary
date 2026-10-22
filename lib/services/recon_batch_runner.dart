typedef ReconScan<T> = Future<T> Function(String address);
typedef ReconResultCheckpoint<T> = Future<void> Function(
  String address,
  T result,
);
typedef ReconFailureCheckpoint = Future<void> Function(
  String address,
  Object error,
  StackTrace stackTrace,
);

/// Runs target reconnaissance concurrently while checkpointing each target as
/// soon as it finishes. One failed target cannot discard successful siblings.
class ReconBatchRunner {
  const ReconBatchRunner._();

  static Future<void> run<T>({
    required List<String> addresses,
    required ReconScan<T> scan,
    required ReconResultCheckpoint<T> onResult,
    required ReconFailureCheckpoint onError,
  }) async {
    await Future.wait(
      addresses.map((address) async {
        late T result;
        try {
          result = await scan(address);
        } catch (error, stackTrace) {
          await onError(address, error, stackTrace);
          return;
        }
        await onResult(address, result);
      }),
    );
  }
}
