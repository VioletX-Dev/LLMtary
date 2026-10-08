import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/material.dart';

import '../database/database_helper.dart';
import '../models/evidence_artifact.dart';
import '../models/project.dart';
import '../models/vulnerability.dart';
import '../services/evidence_storage_service.dart';
import '../utils/file_dialog.dart';

class EvidenceDialog extends StatefulWidget {
  final Project project;
  final Vulnerability vulnerability;
  final Future<List<EvidenceArtifact>> Function()? loadEvidence;

  const EvidenceDialog({
    super.key,
    required this.project,
    required this.vulnerability,
    this.loadEvidence,
  });

  @override
  State<EvidenceDialog> createState() => _EvidenceDialogState();
}

class _EvidenceDialogState extends State<EvidenceDialog> {
  static const _cyan = Color(0xFF00F5FF);
  final _captionController = TextEditingController();
  List<EvidenceArtifact> _items = const [];
  bool _loading = true;
  bool _busy = false;
  String? _pendingPath;
  Uint8List? _pendingPreviewBytes;
  EvidenceSource? _pendingSource;
  bool _pendingIsTemporary = false;
  bool _reviewedForSensitiveData = false;

  @override
  void initState() {
    super.initState();
    _reload();
  }

  @override
  void dispose() {
    if (_pendingIsTemporary && _pendingPath != null) {
      try {
        EvidenceStorageService.deleteTemporaryCaptureSync(_pendingPath!);
      } on FileSystemException catch (error) {
        debugPrint('Unable to remove temporary evidence capture: $error');
      }
    }
    _captionController.dispose();
    super.dispose();
  }

  Future<void> _reload() async {
    final vulnerabilityId = widget.vulnerability.id;
    final items = widget.loadEvidence != null
        ? await widget.loadEvidence!()
        : vulnerabilityId == null
        ? const <EvidenceArtifact>[]
        : await DatabaseHelper.getVulnerabilityEvidence(vulnerabilityId);
    if (!mounted) return;
    setState(() {
      _items = items;
      _loading = false;
    });
  }

  Future<void> _importImage() async {
    final result = await FileDialog.pickFiles(
      dialogTitle: 'Import visual evidence',
      allowedExtensions: const ['png', 'jpg', 'jpeg', 'webp'],
    );
    final path = result?.files.single.path;
    if (path == null) return;
    await _setPending(path, EvidenceSource.imported, temporary: false);
  }

  Future<void> _captureScreen() async {
    _message('Screen capture starts in 3 seconds. Show the vulnerable state.');
    String? temporaryPath;
    setState(() => _busy = true);
    try {
      temporaryPath = await EvidenceStorageService.captureDesktop(
        delaySeconds: 3,
      );
      await _setPending(
        temporaryPath,
        EvidenceSource.captured,
        temporary: true,
      );
    } catch (error) {
      _message('Capture failed: $error');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _setPending(
    String path,
    EvidenceSource source, {
    required bool temporary,
  }) async {
    ValidatedEvidenceImage validated;
    try {
      validated = await EvidenceStorageService.validateImageFile(path);
    } catch (_) {
      if (temporary) {
        await EvidenceStorageService.deleteTemporaryCapture(path);
      }
      rethrow;
    }
    final previousPath = _pendingPath;
    final deletePrevious = _pendingIsTemporary && previousPath != null;
    if (deletePrevious && previousPath != path) {
      try {
        await EvidenceStorageService.deleteTemporaryCapture(previousPath);
      } catch (_) {
        if (temporary) {
          await EvidenceStorageService.deleteTemporaryCapture(path);
        }
        rethrow;
      }
    }
    if (mounted) {
      setState(() {
        _pendingPath = path;
        _pendingPreviewBytes = validated.bytes;
        _pendingSource = source;
        _pendingIsTemporary = temporary;
        _reviewedForSensitiveData = false;
      });
    }
  }

  Future<void> _savePending() async {
    final path = _pendingPath;
    final source = _pendingSource;
    if (path == null || source == null || !_reviewedForSensitiveData) return;
    await _store(path, source);
  }

  Future<void> _store(String sourcePath, EvidenceSource source) async {
    final vulnerabilityId = widget.vulnerability.id;
    if (vulnerabilityId == null || widget.project.id == null) {
      _message('Save the project and finding before attaching evidence.');
      return;
    }
    setState(() => _busy = true);
    try {
      final artifact = await EvidenceStorageService.importImage(
        project: widget.project,
        vulnerabilityId: vulnerabilityId,
        sourcePath: sourcePath,
        caption: _captionController.text,
        source: source,
      );
      try {
        await DatabaseHelper.insertEvidenceArtifact(artifact);
      } catch (_) {
        await EvidenceStorageService.deleteEvidenceFile(
          project: widget.project,
          artifact: artifact,
        );
        rethrow;
      }
      _captionController.clear();
      final temporaryPath = _pendingIsTemporary ? _pendingPath : null;
      setState(() {
        _pendingPath = null;
        _pendingPreviewBytes = null;
        _pendingSource = null;
        _pendingIsTemporary = false;
        _reviewedForSensitiveData = false;
      });
      if (temporaryPath != null) {
        try {
          await EvidenceStorageService.deleteTemporaryCapture(temporaryPath);
        } catch (error) {
          _message(
            'Evidence saved; temporary cleanup will retry later: $error',
          );
        }
      }
      await _reload();
      _message('Visual evidence attached.');
    } catch (error) {
      _message('Unable to attach evidence: $error');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _delete(EvidenceArtifact artifact) async {
    if (artifact.id == null) return;
    setState(() => _busy = true);
    try {
      final staged = await EvidenceStorageService.stageEvidenceDeletion(
        project: widget.project,
        artifact: artifact,
      );
      try {
        final deleted = await DatabaseHelper.deleteEvidenceArtifact(
          artifact.id!,
        );
        if (deleted == null) {
          throw StateError('Evidence record no longer exists');
        }
      } catch (_) {
        await EvidenceStorageService.restoreStagedDeletion(staged);
        rethrow;
      }
      try {
        await EvidenceStorageService.finalizeStagedDeletion(staged);
      } on FileSystemException catch (error) {
        _message('Evidence removed; private file cleanup is pending: $error');
      }
      await _reload();
    } catch (error) {
      _message('Unable to delete evidence: $error');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  void _message(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(
      context,
    ).showSnackBar(SnackBar(content: Text(message)));
  }

  @override
  Widget build(BuildContext context) {
    return Dialog(
      backgroundColor: const Color(0xFF12172E),
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 820, maxHeight: 680),
        child: Padding(
          padding: const EdgeInsets.all(20),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  const Icon(Icons.photo_camera, color: _cyan),
                  const SizedBox(width: 10),
                  const Expanded(
                    child: Text(
                      'VISUAL EVIDENCE',
                      style: TextStyle(
                        color: _cyan,
                        fontWeight: FontWeight.bold,
                        letterSpacing: 1.2,
                      ),
                    ),
                  ),
                  IconButton(
                    onPressed: () => Navigator.of(context).maybePop(),
                    icon: const Icon(Icons.close, color: Colors.white54),
                  ),
                ],
              ),
              Text(
                widget.vulnerability.problem,
                style: const TextStyle(color: Colors.white70, fontSize: 13),
              ),
              const SizedBox(height: 14),
              TextField(
                controller: _captionController,
                maxLength: EvidenceStorageService.maxCaptionCharacters,
                style: const TextStyle(color: Colors.white),
                decoration: const InputDecoration(
                  labelText: 'Evidence caption',
                  hintText:
                      'Describe the vulnerable state shown and why it proves the issue',
                  border: OutlineInputBorder(),
                ),
              ),
              Row(
                children: [
                  Expanded(
                    child: ElevatedButton.icon(
                      onPressed: _busy ? null : _captureScreen,
                      icon: const Icon(Icons.screenshot_monitor),
                      label: const Text('Capture Screen (3s)'),
                    ),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: OutlinedButton.icon(
                      onPressed: _busy ? null : _importImage,
                      icon: const Icon(Icons.upload_file),
                      label: const Text('Import Image'),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 10),
              if (_pendingPreviewBytes != null)
                Container(
                  height: 110,
                  width: double.infinity,
                  color: Colors.black26,
                  child: Image.memory(
                    _pendingPreviewBytes!,
                    fit: BoxFit.contain,
                    cacheWidth: 640,
                    cacheHeight: 360,
                    errorBuilder: (_, __, ___) => const Center(
                      child: Text(
                        'Preview unavailable.',
                        style: TextStyle(color: Colors.orangeAccent),
                      ),
                    ),
                  ),
                ),
              CheckboxListTile(
                contentPadding: EdgeInsets.zero,
                dense: true,
                value: _reviewedForSensitiveData,
                onChanged: _pendingPath == null || _busy
                    ? null
                    : (value) => setState(
                        () => _reviewedForSensitiveData = value ?? false,
                      ),
                title: const Text(
                  'I reviewed this image and confirm passwords, tokens, cookies, '
                  'private keys, and unrelated personal data are not visible.',
                  style: TextStyle(color: Colors.white70, fontSize: 12),
                ),
                controlAffinity: ListTileControlAffinity.leading,
              ),
              SizedBox(
                width: double.infinity,
                child: FilledButton.icon(
                  onPressed:
                      _pendingPath != null &&
                          _reviewedForSensitiveData &&
                          !_busy
                      ? _savePending
                      : null,
                  icon: const Icon(Icons.verified_user_outlined),
                  label: const Text('Save Reviewed Evidence'),
                ),
              ),
              const SizedBox(height: 14),
              const Divider(color: Colors.white12),
              Expanded(
                child: _loading
                    ? const Center(
                        child: CircularProgressIndicator(color: _cyan),
                      )
                    : _items.isEmpty
                    ? const Center(
                        child: Text(
                          'No visual evidence attached to this finding.',
                          style: TextStyle(color: Colors.white38),
                        ),
                      )
                    : ListView.separated(
                        itemCount: _items.length,
                        separatorBuilder: (_, __) =>
                            const Divider(color: Colors.white12),
                        itemBuilder: (context, index) {
                          final item = _items[index];
                          return ListTile(
                            contentPadding: EdgeInsets.zero,
                            leading: SizedBox(
                              width: 100,
                              height: 64,
                              child: FutureBuilder<Uint8List>(
                                future:
                                    EvidenceStorageService.loadEvidenceBytes(
                                      project: widget.project,
                                      artifact: item,
                                    ),
                                builder: (context, snapshot) => snapshot.hasData
                                    ? Image.memory(
                                        snapshot.data!,
                                        fit: BoxFit.cover,
                                        errorBuilder: (_, __, ___) =>
                                            const Icon(Icons.broken_image),
                                      )
                                    : const Center(
                                        child: CircularProgressIndicator(
                                          strokeWidth: 2,
                                        ),
                                      ),
                              ),
                            ),
                            title: Text(
                              item.caption.isEmpty
                                  ? item.fileName
                                  : item.caption,
                              style: const TextStyle(color: Colors.white),
                            ),
                            subtitle: Text(
                              '${item.source.name} · ${item.capturedAt.toLocal()}\n'
                              'SHA-256 ${item.sha256}',
                              maxLines: 2,
                              overflow: TextOverflow.ellipsis,
                              style: const TextStyle(
                                color: Colors.white38,
                                fontSize: 10,
                                fontFamily: 'monospace',
                              ),
                            ),
                            trailing: IconButton(
                              tooltip: 'Delete evidence',
                              onPressed: _busy ? null : () => _delete(item),
                              icon: const Icon(
                                Icons.delete_outline,
                                color: Colors.redAccent,
                              ),
                            ),
                          );
                        },
                      ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
