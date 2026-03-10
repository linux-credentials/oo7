#!/usr/bin/env bash
set -e

# Crypto features to test
CRYPTO_FEATURES=("native_crypto" "openssl_crypto")
PROMPTERS=("gnome" "plasma")

mkdir -p coverage-raw

# Test oo7 package with all crypto features
for crypto in "${CRYPTO_FEATURES[@]}"; do
  echo "🧪 Generating coverage for oo7::${crypto}/tokio..."
  cargo tarpaulin \
    --package oo7 \
    --no-default-features \
    --features "tracing,tokio,${crypto}" \
    --ignore-panics \
    --out Lcov \
    --output-dir coverage-raw
  mv coverage-raw/lcov.info "coverage-raw/${crypto}-tokio.info"
  echo ""
done

# Test daemon with all prompter/crypto combinations
for prompter in "${PROMPTERS[@]}"; do
  for crypto in "${CRYPTO_FEATURES[@]}"; do
    echo ""
    echo "🧪 Generating coverage for oo7-daemon::${prompter}_${crypto}..."
    OO7_DAEMON_PROMPTER_TEST="${prompter}" cargo tarpaulin \
      --package oo7-daemon \
      --no-default-features \
      --features "${crypto}" \
      --ignore-panics \
      --out Lcov \
      --output-dir coverage-raw
    mv coverage-raw/lcov.info "coverage-raw/daemon-${prompter}_${crypto}.info"
  done
done

echo ""
echo "📊 Merging coverage reports..."
mkdir -p coverage/html

# Merge LCOV files
cat coverage-raw/*.info > coverage-raw/combined.info

# Generate JSON report with grcov
grcov coverage-raw/combined.info \
  --binary-path target/debug/ \
  --source-dir . \
  --output-type covdir \
  --output-path coverage/coverage.json \
  --branch \
  --ignore-not-existing \
  --ignore "**/portal/*" \
  --ignore "**/python/*" \
  --ignore "**/cli/*" \
  --ignore "**/pam/*" \
  --ignore "**/tests/*" \
  --ignore "**/examples/*" \
  --ignore "**/target/*" \
  --ignore "**/error.rs"

# Generate HTML report with grcov
grcov coverage-raw/combined.info \
  --binary-path target/debug/ \
  --source-dir . \
  --output-type html \
  --output-path coverage \
  --branch \
  --ignore-not-existing \
  --ignore "**/portal/*" \
  --ignore "**/python/*" \
  --ignore "**/cli/*" \
  --ignore "**/pam/*" \
  --ignore "**/tests/*" \
  --ignore "**/examples/*" \
  --ignore "**/target/*" \
  --ignore "**/error.rs"

# Extract and display coverage percentage
if [ -f coverage/html/coverage.json ]; then
  COVERAGE=$(jq -r '.message' coverage/html/coverage.json | sed 's/%//')
  echo ""
  echo "✅ Combined coverage: ${COVERAGE}%"
  echo "📁 HTML report available at: coverage/html/index.html"
  echo "📁 JSON report available at: coverage/coverage.json"
else
  echo "⚠️  Warning: coverage.json not found"
fi

# Clean up raw files
rm -rf coverage-raw

echo ""
echo "🎉 Coverage generation complete!"
