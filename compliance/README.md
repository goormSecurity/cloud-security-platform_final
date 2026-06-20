# Compliance report renderer

This module currently renders a demonstration HTML/PDF audit report from
`dummy_data.json`. It does not yet collect live evidence from AWS, GitHub, or
the Analyzer.

## Run

```powershell
python -m pip install -r compliance/requirements.txt
python -m playwright install chromium
python compliance/render.py
```

Generated files are written to `compliance/output/` and are ignored by Git.

## Remaining integration

- Replace `dummy_data.json` with an explicit input argument.
- Map the current Analyzer JSON schema to the report schema.
- Collect verified WAF, CloudTrail, S3, and GitHub evidence.
- Mark unavailable evidence as unavailable instead of treating sample values
  as verified evidence.
