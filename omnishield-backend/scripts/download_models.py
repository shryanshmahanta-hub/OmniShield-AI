#!/usr/bin/env python3
"""Download optional Hugging Face model files locally, without running inference."""
from __future__ import annotations
import argparse
from pathlib import Path

MODELS = {
    "sms": "omarash/sms-spam-distilbert",
    "email": "dima806/phishing-email-detection",
    "url": "ealvaradob/bert-finetuned-phishing",
    "prompt-injection": "protectai/deberta-v3-base-prompt-injection-v2",
    "dlp-ner": "dslim/bert-base-NER",
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tasks", nargs="+", choices=[*MODELS, "all"], default=["sms", "email", "url", "prompt-injection"])
    parser.add_argument("--destination", default="models", help="Directory for downloaded model files")
    args = parser.parse_args()
    try:
        from huggingface_hub import snapshot_download
    except ImportError:
        print("Install optional dependencies first: pip install -r requirements-ml.txt")
        return 2
    tasks = list(MODELS) if "all" in args.tasks else args.tasks
    root = Path(args.destination).resolve()
    root.mkdir(parents=True, exist_ok=True)
    for task in tasks:
        repo = MODELS[task]
        target = root / task
        print(f"Downloading {repo} to {target} ...")
        snapshot_download(
            repo_id=repo,
            local_dir=str(target),
            local_files_only=False,
            allow_patterns=["*.json", "*.txt", "*.model", "*.safetensors", "*.bin", "tokenizer*", "vocab*", "merges.txt", "special_tokens_map.json", "sentencepiece.bpe.model"],
        )
        config_path = target / "config.json"
        if config_path.exists():
            import json
            config = json.loads(config_path.read_text(encoding="utf-8"))
            print("Model id2label:", config.get("id2label", "not provided"))
            print("num_labels:", config.get("num_labels", "not provided"))
        print(f"Downloaded {task}. Set its corresponding *_ML_MODEL environment variable to: {target}")
    print("Review each model card, license, label mapping and task suitability before production use.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
