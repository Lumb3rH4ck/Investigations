# Analysis Scripts — ID-5864757

## Scripts

| File | Purpose |
|------|---------|
| `deep_analyze2.py` | Full .NET metadata extraction using dnfile (types, methods, member refs, type refs, fields, params) |
| `extract_us.py` | Extracts #US (User Strings) heap from .NET metadata — reveals URLs, endpoints, behavioral strings |
| `dotnet_scan.py` | Stream-level .NET metadata parsing + embedded file detection + string extraction |
| `il_analysis.py` | IL code extraction from method bodies |
| `extract_dotnet.py` | Basic .NET metadata parsing with pefile |

## Usage

All scripts are designed to run inside the `re-full` Docker container:

```bash
docker run --rm --network none --cap-drop ALL --read-only --tmpfs /tmp:exec \
    -v /path/to/sample.exe:/sample.exe:ro \
    -v /path/to/scripts:/scripts:ro \
    --entrypoint python3 \
    re-full /scripts/deep_analyze2.py
```

## Requirements

- Python 3.11+
- `dnfile` 0.18+
- `pefile` 2024.8+
- Docker with `re-full` image
