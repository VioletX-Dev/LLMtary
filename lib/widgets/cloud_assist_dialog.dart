import 'package:flutter/material.dart';

import '../models/llm_provider.dart';

class CloudAssistConfiguration {
  final bool enabled;
  final LLMProvider provider;
  final bool findingReview;
  final bool reportReview;
  final double budgetUsd;

  const CloudAssistConfiguration({
    required this.enabled,
    required this.provider,
    required this.findingReview,
    required this.reportReview,
    required this.budgetUsd,
  });
}

Future<CloudAssistConfiguration?> showCloudAssistDialog(
  BuildContext context, {
  bool enabled = false,
  LLMProvider provider = LLMProvider.chatGPT,
  bool findingReview = false,
  bool reportReview = false,
  double budgetUsd = 0,
}) {
  return showDialog<CloudAssistConfiguration>(
    context: context,
    builder: (_) => _CloudAssistDialog(
      enabled: enabled,
      provider: provider,
      findingReview: findingReview,
      reportReview: reportReview,
      budgetUsd: budgetUsd,
    ),
  );
}

class _CloudAssistDialog extends StatefulWidget {
  final bool enabled;
  final LLMProvider provider;
  final bool findingReview;
  final bool reportReview;
  final double budgetUsd;

  const _CloudAssistDialog({
    required this.enabled,
    required this.provider,
    required this.findingReview,
    required this.reportReview,
    required this.budgetUsd,
  });

  @override
  State<_CloudAssistDialog> createState() => _CloudAssistDialogState();
}

class _CloudAssistDialogState extends State<_CloudAssistDialog> {
  late bool _enabled;
  late LLMProvider _provider;
  late bool _findingReview;
  late bool _reportReview;
  late final TextEditingController _budgetController;
  String? _error;

  static const _cloudProviders = <LLMProvider>[
    LLMProvider.chatGPT,
    LLMProvider.claude,
    LLMProvider.gemini,
    LLMProvider.openRouter,
  ];

  @override
  void initState() {
    super.initState();
    _enabled = widget.enabled;
    _provider = _cloudProviders.contains(widget.provider)
        ? widget.provider
        : LLMProvider.chatGPT;
    _findingReview = widget.findingReview;
    _reportReview = widget.reportReview;
    _budgetController = TextEditingController(
      text: widget.budgetUsd > 0 ? widget.budgetUsd.toStringAsFixed(2) : '',
    );
  }

  @override
  void dispose() {
    _budgetController.dispose();
    super.dispose();
  }

  void _save() {
    if (!_enabled) {
      Navigator.of(context).pop(
        CloudAssistConfiguration(
          enabled: false,
          provider: _provider,
          findingReview: false,
          reportReview: false,
          budgetUsd: 0,
        ),
      );
      return;
    }
    final budget = double.tryParse(_budgetController.text.trim());
    if (!_findingReview && !_reportReview) {
      setState(() => _error = 'Select at least one optional review phase.');
      return;
    }
    if (budget == null || budget <= 0) {
      setState(() => _error = 'Enter a positive cloud budget in USD.');
      return;
    }
    Navigator.of(context).pop(
      CloudAssistConfiguration(
        enabled: true,
        provider: _provider,
        findingReview: _findingReview,
        reportReview: _reportReview,
        budgetUsd: budget,
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      backgroundColor: const Color(0xFF14182E),
      title: const Text('OPTIONAL CLOUD ASSIST'),
      content: SizedBox(
        width: 480,
        child: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text(
                'Local completion never depends on cloud. If the provider is unavailable or the cap is reached, LLMtary records the skip and completes locally.',
                style: TextStyle(color: Colors.white70),
              ),
              const SizedBox(height: 12),
              CheckboxListTile(
                contentPadding: EdgeInsets.zero,
                value: _enabled,
                title: const Text('Enable optional cloud assistance'),
                onChanged: (value) => setState(() {
                  _enabled = value ?? false;
                  _error = null;
                }),
              ),
              if (_enabled) ...[
                DropdownButtonFormField<LLMProvider>(
                  initialValue: _provider,
                  decoration: const InputDecoration(
                    labelText: 'Cloud provider',
                  ),
                  items: _cloudProviders
                      .map(
                        (provider) => DropdownMenuItem(
                          value: provider,
                          child: Text(provider.displayName),
                        ),
                      )
                      .toList(),
                  onChanged: (value) => setState(() {
                    if (value != null) _provider = value;
                  }),
                ),
                CheckboxListTile(
                  contentPadding: EdgeInsets.zero,
                  value: _findingReview,
                  title: const Text('Final finding confirmation'),
                  onChanged: (value) =>
                      setState(() => _findingReview = value ?? false),
                ),
                CheckboxListTile(
                  contentPadding: EdgeInsets.zero,
                  value: _reportReview,
                  title: const Text('Final report review'),
                  onChanged: (value) =>
                      setState(() => _reportReview = value ?? false),
                ),
                TextField(
                  controller: _budgetController,
                  keyboardType: const TextInputType.numberWithOptions(
                    decimal: true,
                  ),
                  decoration: const InputDecoration(
                    labelText: 'Cloud review cap (USD)',
                    prefixText: r'$ ',
                  ),
                ),
              ],
              if (_error != null) ...[
                const SizedBox(height: 10),
                Text(_error!, style: const TextStyle(color: Colors.redAccent)),
              ],
            ],
          ),
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: const Text('CANCEL'),
        ),
        FilledButton(onPressed: _save, child: const Text('SAVE')),
      ],
    );
  }
}
