# Dataset assets and downloads

The ZIP ships with `manifest.json` and `demo_cases.jsonl`. The JSONL file is synthetic demo/smoke-test material and is **not** a training corpus. The third-party datasets themselves are not included.

From the `omnishield-backend` directory, after reviewing each source's license and privacy terms:

```bash
python scripts/download_datasets.py --sms
python scripts/download_datasets.py --email
# Large optional PE-feature archive; make sure you have sufficient disk space.
python scripts/download_datasets.py --ember2018
```

Downloads are written into `datasets/raw/`; they are intentionally excluded from the distributable ZIP. Do not upload raw datasets or trained weights without confirming their licensing and provenance.

## Task-to-data/model mapping

- SMS/chat scams: UCI SMS Spam Collection can provide a baseline for spam/smishing language, but it is old and not representative of every current financial scam.
- Email phishing: the linked public phishing-email corpus is one potential training/evaluation source. Verify its card, license, labels, duplicates, and source contamination before use.
- URL/domain reputation: use lexical/domain features plus a separately evaluated URL classifier and optional configured reputation provider. Do not train on labels inferred from the demo data.
- Prompt injection: the ProtectAI model is an optional starting point for English prompt-injection detection, not a universal jailbreak detector.
- DLP: deterministic patterns are primary; the optional local named-entity model only augments PERSON/ORG/LOCATION detection.
- QR scams: decode the QR payload and analyze its URL/payment URI. QR is a carrier format, not a single scam class.
- Malware: ClamAV or a trusted private inference service can be configured. EMBER is a PE feature benchmark; it is not a universal file malware corpus or a drop-in live scanner.
- Invoice fraud: the current vendor register is synthetic. A real invoice fraud model requires licensed, representative labeled documents or validated organization-specific transaction history, not the synthetic demo fixtures.
