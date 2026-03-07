#!/usr/bin/env bash
set -e

echo "🧪 Generating coverage for oo7::native_crypto/tokio..."
mkdir -p coverage-raw
cargo tarpaulin \
  --package oo7 \
  --no-default-features \
  --features "tracing,tokio,native_crypto" \
  --ignore-panics \
  --out Lcov \
  --output-dir coverage-raw
mv coverage-raw/lcov.info coverage-raw/native-tokio.info

echo ""
echo "🧪 Generating coverage for oo7::openssl_crypto/tokio..."
cargo tarpaulin \
  --package oo7 \
  --no-default-features \
  --features "tracing,tokio,openssl_crypto" \
  --ignore-panics \
  --out Lcov \
  --output-dir coverage-raw
mv coverage-raw/lcov.info coverage-raw/openssl-tokio.info

echo ""
echo "🧪 Generating coverage for oo7-daemon::native_crypto..."
cargo tarpaulin \
  --package oo7-daemon \
  --no-default-features \
  --features "native_crypto" \
  --ignore-panics \
  --out Lcov \
  --output-dir coverage-raw
mv coverage-raw/lcov.info coverage-raw/daemon-native_crypto.info

echo ""
echo "🧪 Generating coverage for oo7-daemon::openssl_crypto..."
cargo tarpaulin \
  --package oo7-daemon \
  --no-default-features \
  --features "openssl_crypto" \
  --ignore-panics \
  --out Lcov \
  --output-dir coverage-raw
mv coverage-raw/lcov.info coverage-raw/daemon-openssl_crypto.info

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
