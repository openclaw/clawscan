#!/usr/bin/env bash
set -euo pipefail
: "${MACOS_SIGNING_P12:?}" "${MACOS_SIGNING_P12_PASSWORD:?}"
: "${ASC_KEY_ID:?}" "${ASC_ISSUER_ID:?}" "${ASC_PRIVATE_KEY_P8:?}" "${TAG:?}"
keychain="$RUNNER_TEMP/clawscan-signing.keychain-db"
p12="$RUNNER_TEMP/clawscan.p12"
p8="$RUNNER_TEMP/clawscan-notary.p8"
original="$RUNNER_TEMP/clawscan-keychains.txt"
security list-keychains -d user > "$original"
cleanup() {
  restored=()
  while IFS= read -r entry; do
    entry=${entry#"${entry%%[![:space:]]*}"}; entry=${entry#\"}; entry=${entry%\"}
    [[ -z "$entry" ]] || restored+=("$entry")
  done < "$original"
  security list-keychains -d user -s "${restored[@]}"
  security delete-keychain "$keychain" || true
  rm -f "$p12" "$p8" "$original"
}
trap cleanup EXIT
phrase=$(openssl rand -hex 24)
printf '%s' "$MACOS_SIGNING_P12" | base64 -D > "$p12"
printf '%s' "$ASC_PRIVATE_KEY_P8" > "$p8"
chmod 600 "$p12" "$p8"
security create-keychain -p "$phrase" "$keychain"
security unlock-keychain -p "$phrase" "$keychain"
security import "$p12" -k "$keychain" -P "$MACOS_SIGNING_P12_PASSWORD" -T /usr/bin/codesign -T /usr/bin/security
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$phrase" "$keychain" >/dev/null
security list-keychains -d user -s "$keychain"
for architecture in amd64 arm64; do
  name="clawscan_${TAG}_darwin_${architecture}"
  binary="dist/$name/clawscan"
  codesign --force --options runtime --timestamp --identifier ai.openclaw.clawscan \
    --sign 'Developer ID Application: OpenClaw Foundation (FWJYW4S8P8)' "$binary"
  codesign --verify --strict "$binary"
  zip -j "$RUNNER_TEMP/$name.zip" "$binary"
  xcrun notarytool submit "$RUNNER_TEMP/$name.zip" --key "$p8" --key-id "$ASC_KEY_ID" \
    --issuer "$ASC_ISSUER_ID" --wait --output-format json > "$RUNNER_TEMP/$name-notary.json"
  python3 -c 'import json,sys; assert json.load(open(sys.argv[1]))["status"] == "Accepted"' "$RUNNER_TEMP/$name-notary.json"
  codesign --verify --strict --check-notarization -R=notarized "$binary"
  tar -czf "dist/$name.tar.gz" -C dist "$name"
done
