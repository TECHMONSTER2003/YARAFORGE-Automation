"""yaraforge - automated, evidence-driven YARA rule generation for malware families.

Pipeline (static only - samples are never executed):

    triage (hashes, file type, PE header, imports, entropy)
      -> string extraction (ASCII / UTF-16LE) + FLOSS (decoded / stack / tight)
      -> capa capability detection mapped to MITRE ATT&CK
      -> candidate scoring against a goodware baseline
      -> YARA rule synthesis (strings rule + import baseline rule)
      -> evaluation (confusion matrix, leave-one-out cross-validation)
      -> reporting (rule .yar, JSON, IOC CSV, Markdown summary, logs)
"""

__version__ = "1.0.0"
