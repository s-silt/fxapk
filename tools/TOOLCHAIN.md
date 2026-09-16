# Reproducible analysis tools

Run fxapk and install its Python tools with the same interpreter:

```powershell
.venv\Scripts\python.exe -m pip install -r tools/toolchain-requirements.txt
.venv\Scripts\python.exe -m pip check
.venv\Scripts\fxapk.exe doctor --no-fix --serial <your-test-device>
```

Install mitmproxy 12.2.3 in a separate Python 3.12+ environment and explicitly map
its `mitmdump`, `mitmproxy` and `mitmweb` console scripts in the configuration below.
On Python 3.12, mitmproxy's typing-extensions upper bound conflicts with recent
Pydantic versions. Do not downgrade unrelated project packages to force them into
one environment. Run `pip check` in both environments. Core static analysis still
supports the Python versions declared by the project.

```powershell
.venv\Scripts\python.exe -m venv .venv/toolchain/mitmproxy-env
.venv/toolchain/mitmproxy-env/Scripts/python.exe -m pip install mitmproxy==12.2.3
.venv/toolchain/mitmproxy-env/Scripts/python.exe -m pip check
```

Python command resolution prefers console scripts in the current interpreter's
scripts directory, then falls back to PATH. This prevents an unactivated venv
from silently calling another Python installation's Frida or mitmproxy.
Frozen application dispatch is unchanged.

For independently installed native tools, create `fxapk-tools.json` under
`sys.prefix` (normally `.venv/fxapk-tools.json`). Its format is:

```json
{
  "schema": 1,
  "tools": {
    "jadx": "C:/analysis-tools/jadx/bin/jadx.bat",
    "apktool": "C:/analysis-tools/apktool/apktool.bat",
    "adb": "C:/analysis-tools/platform-tools/adb.exe",
    "tshark": "C:/analysis-tools/wireshark/tshark.exe",
    "mitmdump": "C:/analysis-tools/mitmproxy-env/Scripts/mitmdump.exe",
    "mitmproxy": "C:/analysis-tools/mitmproxy-env/Scripts/mitmproxy.exe",
    "mitmweb": "C:/analysis-tools/mitmproxy-env/Scripts/mitmweb.exe"
  }
}
```

Use your own absolute executable paths. `FXAPK_TOOLCHAIN_FILE` selects an alternate
configuration file. An explicitly selected but missing executable, invalid JSON,
or unsupported schema fails closed and logs a warning instead of silently falling
back to a different tool version. Unlisted tools retain their normal discovery.
JADX's existing addon fallback remains available when no explicit selection exists.
The optional configuration is local machine data; do not commit it or ship it as
another computer's configuration. No permanent PATH changes are required.
`fxapk-tools.json` is trusted local execution configuration whose paths are maintained
by the local administrator; Windows `.bat` tools involve a command-interpreter execution chain.
For manual PowerShell use, `. ./tools/Use-Toolchain.ps1` selects these same tools
in the current session. It checks all configured analysis tools before changing
the session PATH. Running the project Python directly already uses the selection
inside fxapk; dot-sourcing is only needed for bare commands such as `jadx`.
Unlike fxapk's own resolution, the session script requires every listed tool to be
ready and does not support the JADX addon fallback.

The tested native release targets are JADX 1.5.6, Apktool 3.0.3, Android
Platform-Tools 37.0.1 and Wireshark/TShark 4.6.8 (stable, not the 4.7 development
branch). Download from the respective official publishers, verify their published
checksums, and record exact paths and hashes locally. Apktool is an auxiliary
manual tool; fxapk's current repackager uses ZIP replacement plus SDK signing tools.

Match the device's frida-server to the host Frida version, confirm root, and test
enumeration, native attach and Java bridge operation on an authorized test device.
Do not upgrade another device or replace its system tcpdump as an installation
side effect. A host version check alone is not a dynamic stability test.

For upgrade validation, run the relevant unit tests, lint/type checks and full
test suite, then exercise a synthetic APK and a controlled local HTTP exchange.
Record any skipped integration checks. Preserve existing evidence and indexes;
tool upgrades do not retroactively revalidate old results.
