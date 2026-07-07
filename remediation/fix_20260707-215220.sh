#!/bin/bash
# ============================================================
# 보안 취약점 수정 스크립트 — 2026-07-07 21:52 KST
# 이 스크립트는 자동 생성됩니다. 실행 전 반드시 검토하세요.
# ============================================================
set -e
REGION=${1:-ap-northeast-2}

# ── [1] [CVE-2019-10082] httpd: read-after-free in h2 connection shutdown (CRITICAL) ──
# 식별자: CVE-2019-10082
# 리소스: vulnerables/web-dvwa

# CVE-2019-10082 — httpd: read-after-free in h2 connection shutdown
# Image: vulnerables/web-dvwa
# 패키지: apache2 2.4.25-3+deb9u5 → 2.4.25-3+deb9u8
# 방법 1: 베이스 이미지 업그레이드 후 재빌드
docker pull vulnerables/web-dvwa:latest
docker build --no-cache -t vulnerables/web-dvwa:patched .

# 방법 2: 컨테이너 내 패키지만 업데이트 (임시 조치)
# apt-get update && apt-get install -y --only-upgrade apache2

# ── [2] [CVE-2021-26691] httpd: mod_session: Heap overflow via a crafted SessionHeader value (CRITICAL) ──
# 식별자: CVE-2021-26691
# 리소스: vulnerables/web-dvwa

# CVE-2021-26691 — httpd: mod_session: Heap overflow via a crafted SessionHeader value
# Image: vulnerables/web-dvwa
# 패키지: apache2 2.4.25-3+deb9u5 → 2.4.25-3+deb9u10
# 방법 1: 베이스 이미지 업그레이드 후 재빌드
docker pull vulnerables/web-dvwa:latest
docker build --no-cache -t vulnerables/web-dvwa:patched .

# 방법 2: 컨테이너 내 패키지만 업데이트 (임시 조치)
# apt-get update && apt-get install -y --only-upgrade apache2

# ── [3] [CVE-2021-39275] httpd: Out-of-bounds write in ap_escape_quotes() via malicious input (CRITICAL) ──
# 식별자: CVE-2021-39275
# 리소스: vulnerables/web-dvwa

# CVE-2021-39275 — httpd: Out-of-bounds write in ap_escape_quotes() via malicious input
# Image: vulnerables/web-dvwa
# 패키지: apache2 2.4.25-3+deb9u5 → 2.4.25-3+deb9u11
# 방법 1: 베이스 이미지 업그레이드 후 재빌드
docker pull vulnerables/web-dvwa:latest
docker build --no-cache -t vulnerables/web-dvwa:patched .

# 방법 2: 컨테이너 내 패키지만 업데이트 (임시 조치)
# apt-get update && apt-get install -y --only-upgrade apache2

# ── [4] [CVE-2021-40438] httpd: mod_proxy: SSRF via a crafted request uri-path containing "unix:" (CRITICAL) ──
# 식별자: CVE-2021-40438
# 리소스: vulnerables/web-dvwa

# CVE-2021-40438 — httpd: mod_proxy: SSRF via a crafted request uri-path containing "unix:"
# Image: vulnerables/web-dvwa
# 패키지: apache2 2.4.25-3+deb9u5 → 2.4.25-3+deb9u11
# 방법 1: 베이스 이미지 업그레이드 후 재빌드
docker pull vulnerables/web-dvwa:latest
docker build --no-cache -t vulnerables/web-dvwa:patched .

# 방법 2: 컨테이너 내 패키지만 업데이트 (임시 조치)
# apt-get update && apt-get install -y --only-upgrade apache2

# ── [5] [CVE-2021-44790] httpd: mod_lua: Possible buffer overflow when parsing multipart content (CRITICAL) ──
# 식별자: CVE-2021-44790
# 리소스: vulnerables/web-dvwa

# CVE-2021-44790 — httpd: mod_lua: Possible buffer overflow when parsing multipart content
# Image: vulnerables/web-dvwa
# 패키지: apache2 2.4.25-3+deb9u5 → 2.4.25-3+deb9u12
# 방법 1: 베이스 이미지 업그레이드 후 재빌드
docker pull vulnerables/web-dvwa:latest
docker build --no-cache -t vulnerables/web-dvwa:patched .

# 방법 2: 컨테이너 내 패키지만 업데이트 (임시 조치)
# apt-get update && apt-get install -y --only-upgrade apache2

# ── [6] [CVE-2022-22720] httpd: Errors encountered during the discarding of request body lead to HTTP req (CRITICAL) ──
# 식별자: CVE-2022-22720
# 리소스: vulnerables/web-dvwa

# CVE-2022-22720 — httpd: Errors encountered during the discarding of request body lead to HTTP req
# Image: vulnerables/web-dvwa
# 패키지: apache2 2.4.25-3+deb9u5 → 2.4.25-3+deb9u13
# 방법 1: 베이스 이미지 업그레이드 후 재빌드
docker pull vulnerables/web-dvwa:latest
docker build --no-cache -t vulnerables/web-dvwa:patched .

# 방법 2: 컨테이너 내 패키지만 업데이트 (임시 조치)
# apt-get update && apt-get install -y --only-upgrade apache2

# ── [7] [CVE-2022-22721] httpd: core: Possible buffer overflow with very large or unlimited LimitXMLReque (CRITICAL) ──
# 식별자: CVE-2022-22721
# 리소스: vulnerables/web-dvwa

# CVE-2022-22721 — httpd: core: Possible buffer overflow with very large or unlimited LimitXMLReque
# Image: vulnerables/web-dvwa
# 패키지: apache2 2.4.25-3+deb9u5 → 2.4.25-3+deb9u13
# 방법 1: 베이스 이미지 업그레이드 후 재빌드
docker pull vulnerables/web-dvwa:latest
docker build --no-cache -t vulnerables/web-dvwa:patched .

# 방법 2: 컨테이너 내 패키지만 업데이트 (임시 조치)
# apt-get update && apt-get install -y --only-upgrade apache2

# ── [8] [CVE-2022-23943] httpd: mod_sed: Read/write beyond bounds (CRITICAL) ──
# 식별자: CVE-2022-23943
# 리소스: vulnerables/web-dvwa

# CVE-2022-23943 — httpd: mod_sed: Read/write beyond bounds
# Image: vulnerables/web-dvwa
# 패키지: apache2 2.4.25-3+deb9u5 → 2.4.25-3+deb9u13
# 방법 1: 베이스 이미지 업그레이드 후 재빌드
docker pull vulnerables/web-dvwa:latest
docker build --no-cache -t vulnerables/web-dvwa:patched .

# 방법 2: 컨테이너 내 패키지만 업데이트 (임시 조치)
# apt-get update && apt-get install -y --only-upgrade apache2

# ── [9] [CVE-2023-46233] crypto-js: PBKDF2 1,000 times weaker than specified in 1993 and 1.3M times weake (CRITICAL) ──
# 식별자: CVE-2023-46233
# 리소스: bkimminich/juice-shop

# CVE-2023-46233 — crypto-js: PBKDF2 1,000 times weaker than specified in 1993 and 1.3M times weake
# Image: bkimminich/juice-shop
# 패키지: crypto-js 3.3.0 → 4.2.0
# 방법 1: 베이스 이미지 업그레이드 후 재빌드
docker pull bkimminich/juice-shop:latest
docker build --no-cache -t bkimminich/juice-shop:patched .

# 방법 2: 컨테이너 내 패키지만 업데이트 (임시 조치)
# apt-get update && apt-get install -y --only-upgrade crypto-js

# ── [10] [CVE-2026-53486] Decompress: Archive extraction can create files and links outside of the target  (CRITICAL) ──
# 식별자: CVE-2026-53486
# 리소스: bkimminich/juice-shop

# CVE-2026-53486 — Decompress: Archive extraction can create files and links outside of the target 
# Image: bkimminich/juice-shop
# 패키지: decompress 4.2.1 → 최신 버전
# 방법 1: 베이스 이미지 업그레이드 후 재빌드
docker pull bkimminich/juice-shop:latest
docker build --no-cache -t bkimminich/juice-shop:patched .

# 방법 2: 컨테이너 내 패키지만 업데이트 (임시 조치)
# apt-get update && apt-get install -y --only-upgrade decompress

# ── [11] [CVE-2026-31789] openssl: OpenSSL: Heap buffer overflow on 32-bit systems from large X.509 certif (CRITICAL) ──
# 식별자: CVE-2026-31789
# 리소스: ghost:5-alpine

# CVE-2026-31789 — openssl: OpenSSL: Heap buffer overflow on 32-bit systems from large X.509 certif
# Image: ghost:5-alpine
# 패키지: libcrypto3 3.5.5-r0 → 3.5.6-r0
# 방법 1: 베이스 이미지 업그레이드 후 재빌드
docker pull ghost:latest
docker build --no-cache -t ghost:patched .

# 방법 2: 컨테이너 내 패키지만 업데이트 (임시 조치)
# apt-get update && apt-get install -y --only-upgrade libcrypto3

# ── [12] [CVE-2018-1333] httpd: mod_http2: Too much time allocated to workers, possibly leading to DoS (HIGH) ──
# 식별자: CVE-2018-1333
# 리소스: vulnerables/web-dvwa

# CVE-2018-1333 — httpd: mod_http2: Too much time allocated to workers, possibly leading to DoS
# Image: vulnerables/web-dvwa
# 패키지: apache2 2.4.25-3+deb9u5 → 2.4.25-3+deb9u6
# 방법 1: 베이스 이미지 업그레이드 후 재빌드
docker pull vulnerables/web-dvwa:latest
docker build --no-cache -t vulnerables/web-dvwa:patched .

# 방법 2: 컨테이너 내 패키지만 업데이트 (임시 조치)
# apt-get update && apt-get install -y --only-upgrade apache2

# ── [13] [CVE-2018-17199] httpd: mod_session_cookie does not respect expiry time (HIGH) ──
# 식별자: CVE-2018-17199
# 리소스: vulnerables/web-dvwa

# CVE-2018-17199 — httpd: mod_session_cookie does not respect expiry time
# Image: vulnerables/web-dvwa
# 패키지: apache2 2.4.25-3+deb9u5 → 2.4.25-3+deb9u7
# 방법 1: 베이스 이미지 업그레이드 후 재빌드
docker pull vulnerables/web-dvwa:latest
docker build --no-cache -t vulnerables/web-dvwa:patched .

# 방법 2: 컨테이너 내 패키지만 업데이트 (임시 조치)
# apt-get update && apt-get install -y --only-upgrade apache2

# ── [14] [NSWG-ECO-428] Out-of-bounds Read (HIGH) ──
# 식별자: NSWG-ECO-428
# 리소스: bkimminich/juice-shop

# NSWG-ECO-428 — Out-of-bounds Read
# Image: bkimminich/juice-shop
# 패키지: base64url 0.0.6 → >=3.0.0
# 방법 1: 베이스 이미지 업그레이드 후 재빌드
docker pull bkimminich/juice-shop:latest
docker build --no-cache -t bkimminich/juice-shop:patched .

# 방법 2: 컨테이너 내 패키지만 업데이트 (임시 조치)
# apt-get update && apt-get install -y --only-upgrade base64url

# ── [15] [CVE-2026-28387] openssl: OpenSSL: Arbitrary code execution due to use-after-free in DANE TLSA au (HIGH) ──
# 식별자: CVE-2026-28387
# 리소스: ghost:5-alpine

# CVE-2026-28387 — openssl: OpenSSL: Arbitrary code execution due to use-after-free in DANE TLSA au
# Image: ghost:5-alpine
# 패키지: libcrypto3 3.5.5-r0 → 3.5.6-r0
# 방법 1: 베이스 이미지 업그레이드 후 재빌드
docker pull ghost:latest
docker build --no-cache -t ghost:patched .

# 방법 2: 컨테이너 내 패키지만 업데이트 (임시 조치)
# apt-get update && apt-get install -y --only-upgrade libcrypto3

# ── [16] [CVE-2026-28388] openssl: OpenSSL: Denial of Service due to NULL pointer dereference in delta CRL (HIGH) ──
# 식별자: CVE-2026-28388
# 리소스: ghost:5-alpine

# CVE-2026-28388 — openssl: OpenSSL: Denial of Service due to NULL pointer dereference in delta CRL
# Image: ghost:5-alpine
# 패키지: libcrypto3 3.5.5-r0 → 3.5.6-r0
# 방법 1: 베이스 이미지 업그레이드 후 재빌드
docker pull ghost:latest
docker build --no-cache -t ghost:patched .

# 방법 2: 컨테이너 내 패키지만 업데이트 (임시 조치)
# apt-get update && apt-get install -y --only-upgrade libcrypto3

# ── [17] [CVE-2026-28389] openssl: OpenSSL: Denial of Service vulnerability in CMS processing (HIGH) ──
# 식별자: CVE-2026-28389
# 리소스: ghost:5-alpine

# CVE-2026-28389 — openssl: OpenSSL: Denial of Service vulnerability in CMS processing
# Image: ghost:5-alpine
# 패키지: libcrypto3 3.5.5-r0 → 3.5.6-r0
# 방법 1: 베이스 이미지 업그레이드 후 재빌드
docker pull ghost:latest
docker build --no-cache -t ghost:patched .

# 방법 2: 컨테이너 내 패키지만 업데이트 (임시 조치)
# apt-get update && apt-get install -y --only-upgrade libcrypto3

# ── [18] [CVE-2026-28390] openssl: OpenSSL: Denial of Service due to NULL pointer dereference in CMS Envel (HIGH) ──
# 식별자: CVE-2026-28390
# 리소스: ghost:5-alpine

# CVE-2026-28390 — openssl: OpenSSL: Denial of Service due to NULL pointer dereference in CMS Envel
# Image: ghost:5-alpine
# 패키지: libcrypto3 3.5.5-r0 → 3.5.6-r0
# 방법 1: 베이스 이미지 업그레이드 후 재빌드
docker pull ghost:latest
docker build --no-cache -t ghost:patched .

# 방법 2: 컨테이너 내 패키지만 업데이트 (임시 조치)
# apt-get update && apt-get install -y --only-upgrade libcrypto3

# ── [19] [CVE-2026-45447] openssl: Heap Use-After-Free in OpenSSL PKCS7_verify() (HIGH) ──
# 식별자: CVE-2026-45447
# 리소스: ghost:5-alpine

# CVE-2026-45447 — openssl: Heap Use-After-Free in OpenSSL PKCS7_verify()
# Image: ghost:5-alpine
# 패키지: libcrypto3 3.5.5-r0 → 3.5.7-r0
# 방법 1: 베이스 이미지 업그레이드 후 재빌드
docker pull ghost:latest
docker build --no-cache -t ghost:patched .

# 방법 2: 컨테이너 내 패키지만 업데이트 (임시 조치)
# apt-get update && apt-get install -y --only-upgrade libcrypto3

# ── [20] S3 버킷 KMS 암호화 전환 (MEDIUM) ──
# 식별자: s3_bucket_encryption
# 리소스: aws-waf-logs-cloud-sec-dev

# 1) KMS 키 생성 (이미 있으면 기존 Key ARN 사용)
KEY_ARN=$(aws kms create-key --description 's3-aws-waf-logs-cloud-sec-dev' \
  --region ap-northeast-2 --query KeyMetadata.Arn --output text)

# 2) 버킷 암호화 정책 KMS로 교체
aws s3api put-bucket-encryption \
  --bucket aws-waf-logs-cloud-sec-dev \
  --server-side-encryption-configuration '{
    "Rules": [{"ApplyServerSideEncryptionByDefault": {
      "SSEAlgorithm": "aws:kms",
      "KMSMasterKeyID": "'$KEY_ARN'"
    }}]
  }' \
  --region ap-northeast-2

# ── [21] S3 버킷 KMS 암호화 전환 (MEDIUM) ──
# 식별자: s3_bucket_encryption
# 리소스: cloud-sec-alb-logs-dev

# 1) KMS 키 생성 (이미 있으면 기존 Key ARN 사용)
KEY_ARN=$(aws kms create-key --description 's3-cloud-sec-alb-logs-dev' \
  --region ap-northeast-2 --query KeyMetadata.Arn --output text)

# 2) 버킷 암호화 정책 KMS로 교체
aws s3api put-bucket-encryption \
  --bucket cloud-sec-alb-logs-dev \
  --server-side-encryption-configuration '{
    "Rules": [{"ApplyServerSideEncryptionByDefault": {
      "SSEAlgorithm": "aws:kms",
      "KMSMasterKeyID": "'$KEY_ARN'"
    }}]
  }' \
  --region ap-northeast-2

# ── [22] S3 버킷 KMS 암호화 전환 (MEDIUM) ──
# 식별자: s3_bucket_encryption
# 리소스: cloud-sec-audit-evidence-dev

# 1) KMS 키 생성 (이미 있으면 기존 Key ARN 사용)
KEY_ARN=$(aws kms create-key --description 's3-cloud-sec-audit-evidence-dev' \
  --region ap-northeast-2 --query KeyMetadata.Arn --output text)

# 2) 버킷 암호화 정책 KMS로 교체
aws s3api put-bucket-encryption \
  --bucket cloud-sec-audit-evidence-dev \
  --server-side-encryption-configuration '{
    "Rules": [{"ApplyServerSideEncryptionByDefault": {
      "SSEAlgorithm": "aws:kms",
      "KMSMasterKeyID": "'$KEY_ARN'"
    }}]
  }' \
  --region ap-northeast-2

# ── [23] [CVE-2026-5435] glibc: glibc: Out-of-bounds write via TSIG record processing (MEDIUM) ──
# 식별자: CVE-2026-5435
# 리소스: bkimminich/juice-shop

# CVE-2026-5435 — glibc: glibc: Out-of-bounds write via TSIG record processing
# Image: bkimminich/juice-shop
# 패키지: libc6 2.41-12+deb13u3 → 최신 버전
# 방법 1: 베이스 이미지 업그레이드 후 재빌드
docker pull bkimminich/juice-shop:latest
docker build --no-cache -t bkimminich/juice-shop:patched .

# 방법 2: 컨테이너 내 패키지만 업데이트 (임시 조치)
# apt-get update && apt-get install -y --only-upgrade libc6

# ── [24] [CVE-2026-5450] glibc: glibc: Heap Buffer Overflow in `scanf` with `%mc` format specifier and la (MEDIUM) ──
# 식별자: CVE-2026-5450
# 리소스: bkimminich/juice-shop

# CVE-2026-5450 — glibc: glibc: Heap Buffer Overflow in `scanf` with `%mc` format specifier and la
# Image: bkimminich/juice-shop
# 패키지: libc6 2.41-12+deb13u3 → 최신 버전
# 방법 1: 베이스 이미지 업그레이드 후 재빌드
docker pull bkimminich/juice-shop:latest
docker build --no-cache -t bkimminich/juice-shop:patched .

# 방법 2: 컨테이너 내 패키지만 업데이트 (임시 조치)
# apt-get update && apt-get install -y --only-upgrade libc6

# ── [25] [CVE-2026-5928] glibc: glibc: Information disclosure or denial of service via ungetwc function w (MEDIUM) ──
# 식별자: CVE-2026-5928
# 리소스: bkimminich/juice-shop

# CVE-2026-5928 — glibc: glibc: Information disclosure or denial of service via ungetwc function w
# Image: bkimminich/juice-shop
# 패키지: libc6 2.41-12+deb13u3 → 최신 버전
# 방법 1: 베이스 이미지 업그레이드 후 재빌드
docker pull bkimminich/juice-shop:latest
docker build --no-cache -t bkimminich/juice-shop:patched .

# 방법 2: 컨테이너 내 패키지만 업데이트 (임시 조치)
# apt-get update && apt-get install -y --only-upgrade libc6

# ── [26] [CVE-2026-6238] glibc: glibc: Application crash or uninitialized memory read via crafted DNS res (MEDIUM) ──
# 식별자: CVE-2026-6238
# 리소스: bkimminich/juice-shop

# CVE-2026-6238 — glibc: glibc: Application crash or uninitialized memory read via crafted DNS res
# Image: bkimminich/juice-shop
# 패키지: libc6 2.41-12+deb13u3 → 최신 버전
# 방법 1: 베이스 이미지 업그레이드 후 재빌드
docker pull bkimminich/juice-shop:latest
docker build --no-cache -t bkimminich/juice-shop:patched .

# 방법 2: 컨테이너 내 패키지만 업데이트 (임시 조치)
# apt-get update && apt-get install -y --only-upgrade libc6

# ── [27] [CVE-2026-27171] zlib: zlib: Denial of Service via infinite loop in CRC32 combine functions (MEDIUM) ──
# 식별자: CVE-2026-27171
# 리소스: bkimminich/juice-shop

# CVE-2026-27171 — zlib: zlib: Denial of Service via infinite loop in CRC32 combine functions
# Image: bkimminich/juice-shop
# 패키지: zlib1g 1:1.3.dfsg+really1.3.1-1+b1 → 최신 버전
# 방법 1: 베이스 이미지 업그레이드 후 재빌드
docker pull bkimminich/juice-shop:latest
docker build --no-cache -t bkimminich/juice-shop:patched .

# 방법 2: 컨테이너 내 패키지만 업데이트 (임시 조치)
# apt-get update && apt-get install -y --only-upgrade zlib1g

# ── [28] [GHSA-rvg8-pwq2-xj7q] Out-of-bounds Read in base64url (MEDIUM) ──
# 식별자: GHSA-rvg8-pwq2-xj7q
# 리소스: bkimminich/juice-shop

# GHSA-rvg8-pwq2-xj7q — Out-of-bounds Read in base64url
# Image: bkimminich/juice-shop
# 패키지: base64url 0.0.6 → 3.0.0
# 방법 1: 베이스 이미지 업그레이드 후 재빌드
docker pull bkimminich/juice-shop:latest
docker build --no-cache -t bkimminich/juice-shop:patched .

# 방법 2: 컨테이너 내 패키지만 업데이트 (임시 조치)
# apt-get update && apt-get install -y --only-upgrade base64url

# ── [29] [CVE-2022-41940] engine.io: Specially crafted HTTP request can trigger an uncaught exception (MEDIUM) ──
# 식별자: CVE-2022-41940
# 리소스: bkimminich/juice-shop

# CVE-2022-41940 — engine.io: Specially crafted HTTP request can trigger an uncaught exception
# Image: bkimminich/juice-shop
# 패키지: engine.io 4.1.2 → 3.6.1, 6.2.1
# 방법 1: 베이스 이미지 업그레이드 후 재빌드
docker pull bkimminich/juice-shop:latest
docker build --no-cache -t bkimminich/juice-shop:patched .

# 방법 2: 컨테이너 내 패키지만 업데이트 (임시 조치)
# apt-get update && apt-get install -y --only-upgrade engine.io

# ── [30] [CVE-2026-2673] openssl: OpenSSL TLS 1.3 server may choose unexpected key agreement group (MEDIUM) ──
# 식별자: CVE-2026-2673
# 리소스: ghost:5-alpine

# CVE-2026-2673 — openssl: OpenSSL TLS 1.3 server may choose unexpected key agreement group
# Image: ghost:5-alpine
# 패키지: libcrypto3 3.5.5-r0 → 3.5.6-r0
# 방법 1: 베이스 이미지 업그레이드 후 재빌드
docker pull ghost:latest
docker build --no-cache -t ghost:patched .

# 방법 2: 컨테이너 내 패키지만 업데이트 (임시 조치)
# apt-get update && apt-get install -y --only-upgrade libcrypto3

# ── [31] [CVE-2026-31790] openssl: openssl: Information Disclosure from Uninitialized Memory via Invalid R (MEDIUM) ──
# 식별자: CVE-2026-31790
# 리소스: ghost:5-alpine

# CVE-2026-31790 — openssl: openssl: Information Disclosure from Uninitialized Memory via Invalid R
# Image: ghost:5-alpine
# 패키지: libcrypto3 3.5.5-r0 → 3.5.6-r0
# 방법 1: 베이스 이미지 업그레이드 후 재빌드
docker pull ghost:latest
docker build --no-cache -t ghost:patched .

# 방법 2: 컨테이너 내 패키지만 업데이트 (임시 조치)
# apt-get update && apt-get install -y --only-upgrade libcrypto3

# ── [32] [CVE-2026-34182] openssl: CMS AuthEnvelopedData Processing May Accept Forged Messages (MEDIUM) ──
# 식별자: CVE-2026-34182
# 리소스: ghost:5-alpine

# CVE-2026-34182 — openssl: CMS AuthEnvelopedData Processing May Accept Forged Messages
# Image: ghost:5-alpine
# 패키지: libcrypto3 3.5.5-r0 → 3.5.7-r0
# 방법 1: 베이스 이미지 업그레이드 후 재빌드
docker pull ghost:latest
docker build --no-cache -t ghost:patched .

# 방법 2: 컨테이너 내 패키지만 업데이트 (임시 조치)
# apt-get update && apt-get install -y --only-upgrade libcrypto3

# ── [33] [CVE-2026-34183] openssl: Unbounded Memory Growth in the QUIC PATH_CHALLENGE Handler (MEDIUM) ──
# 식별자: CVE-2026-34183
# 리소스: ghost:5-alpine

# CVE-2026-34183 — openssl: Unbounded Memory Growth in the QUIC PATH_CHALLENGE Handler
# Image: ghost:5-alpine
# 패키지: libcrypto3 3.5.5-r0 → 3.5.7-r0
# 방법 1: 베이스 이미지 업그레이드 후 재빌드
docker pull ghost:latest
docker build --no-cache -t ghost:patched .

# 방법 2: 컨테이너 내 패키지만 업데이트 (임시 조치)
# apt-get update && apt-get install -y --only-upgrade libcrypto3
