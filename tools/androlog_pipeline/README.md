# AndroLog Pipeline Helpers

Reusable helpers for APK instrumentation and 1-minute EchoDroid runs.

Files:
- `instrument_apk_with_androlog.sh` — instrument an APK with AndroLog into an output directory.
-- `run_androlog_faruzan_1min.sh` — install an APK, run a 1-minute faruzan-style EchoDroid session, collect console/activity output, and try to pull `.ec` files.

## Instrument an APK

Example:

./tools/androlog_pipeline/instrument_apk_with_androlog.sh \
  /path/to/app.apk \
  $HOME/Desktop/EchoDroid/EchoDroid/appdata/androzoo_downloads/myapp_androlog_instr \
  MYAPP_LOG

Outputs include:
- `instrument.log`
- `aapt_badging.txt`
- `instrumented_aapt_badging.txt` when an output APK exists
- `run.meta`

## Run an APK for 1 minute

Example for custom pipeline:

./tools/androlog_pipeline/run_androlog_faruzan_1min.sh \
  $HOME/Desktop/EchoDroid/EchoDroid-Fastbot-Custom \
  $HOME/Desktop/EchoDroid/EchoDroid/appdata/androzoo_downloads/myapp_androlog_instr/base.apk \
  com.example.app \
  MyApp \
  MYAPP_LOG \
  myapp_faruzan_custom_1min_validkey \
  $HOME/Desktop/MismatchDroid/MismatchDroid/appdata/androzoo_downloads/myapp_androlog_instr

Arguments:
1. project dir (`EchoDroid-Fastbot` or `EchoDroid-Fastbot-Custom`)
2. APK path to install
3. package name
4. app name
5. AndroLog tag
6. run prefix for output directory naming
7. instrumentation dir, or `-` if not available

The run helper writes:
- `console.txt`
- `coverage_summary.json`
- pulled remote output directory
- `ec_files_on_device.txt`
- `ec_files/` when `.ec` files are found

## Notes

- If AndroLog export fails with `DexPrinterException`, the instrumentation output may not be usable for true method coverage.
- The run helper still records Fastbot console-reported coverage and activity coverage.
- `.ec` pulling is attempted after every run.
