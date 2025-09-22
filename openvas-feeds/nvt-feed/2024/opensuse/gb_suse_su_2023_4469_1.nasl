# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833466");
  script_version("2025-02-26T05:38:41+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-39318", "CVE-2023-39319", "CVE-2023-39320", "CVE-2023-39321", "CVE-2023-39322", "CVE-2023-39323", "CVE-2023-39325", "CVE-2023-44487", "CVE-2023-45283", "CVE-2023-45284");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-12 14:39:48 +0000 (Tue, 12 Sep 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:16:03 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for go1.21 (SUSE-SU-2023:4469-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4469-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/E6FVIHGZLCV4M6XGFEFGBVM3U5PGYSNR");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.21'
  package(s) announced via the SUSE-SU-2023:4469-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for go1.21-openssl fixes the following issues:

  Update to version 1.21.4.1 cut from the go1.21-openssl-fips branch at the
  revision tagged go1.21.4-1-openssl-fips.

  * Update to go1.21.4

  go1.21.4 (released 2023-11-07) includes security fixes to the path/filepath
  package, as well as bug fixes to the linker, the runtime, the compiler, and the
  go/types, net/http, and runtime/cgo packages.

  * security: fix CVE-2023-45283 CVE-2023-45284 path/filepath: insecure parsing
      of Windows paths (bsc#1216943, bsc#1216944)

  * spec: update unification rules

  * cmd/compile: internal compiler error: expected struct value to have type
      struct

  * cmd/link: split text sections for arm 32-bit

  * runtime: MADV_COLLAPSE causes production performance issues on Linux

  * go/types, x/tools/go/ssa: panic: type param without replacement encountered

  * cmd/compile: -buildmode=c-archive produces code not suitable for use in a
      shared object on arm64

  * net/http: http2 page fails on firefox/safari if pushing resources

  Initial package go1.21-openssl version 1.21.3.1 cut from the go1.21-openssl-fips
  branch at the revision tagged go1.21.3-1-openssl-fips. (jsc#SLE-18320)

  * Go upstream merged branch dev.boringcrypto in go1.19+.

  * In go1.x enable BoringCrypto via GOEXPERIMENT=boringcrypto.

  * In go1.x-openssl enable FIPS mode (or boring mode as the package is named)
      either via an environment variable GOLANG_FIPS=1 or by virtue of booting the
      host in FIPS mode.

  * When the operating system is operating in FIPS mode, Go applications which
      import crypto/tls/fipsonly limit operations to the FIPS ciphersuite.

  * go1.x-openssl is delivered as two large patches to go1.x applying necessary
      modifications from the golang-fips/go GitHub project for the Go crypto
      library to use OpenSSL as the external cryptographic library in a FIPS
      compliant way.

  * go1.x-openssl modifies the crypto/* packages to use OpenSSL for
      cryptographic operations.

  * go1.x-openssl uses dlopen() to call into OpenSSL.

  * SUSE RPM packaging introduces a fourth version digit go1.x.y.z corresponding
      to the golang-fips/go patchset tagged revision.

  * Patchset improvements can be updated independently of upstream Go
      maintenance releases.

  ##");

  script_tag(name:"affected", value:"'go1.21' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"go1.21-openssl-doc", rpm:"go1.21-openssl-doc~1.21.4.1~150000.1.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.21-openssl-race", rpm:"go1.21-openssl-race~1.21.4.1~150000.1.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.21-openssl", rpm:"go1.21-openssl~1.21.4.1~150000.1.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.21-openssl-doc", rpm:"go1.21-openssl-doc~1.21.4.1~150000.1.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.21-openssl-race", rpm:"go1.21-openssl-race~1.21.4.1~150000.1.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.21-openssl", rpm:"go1.21-openssl~1.21.4.1~150000.1.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"go1.21-openssl-doc", rpm:"go1.21-openssl-doc~1.21.4.1~150000.1.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.21-openssl-race", rpm:"go1.21-openssl-race~1.21.4.1~150000.1.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.21-openssl", rpm:"go1.21-openssl~1.21.4.1~150000.1.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.21-openssl-doc", rpm:"go1.21-openssl-doc~1.21.4.1~150000.1.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.21-openssl-race", rpm:"go1.21-openssl-race~1.21.4.1~150000.1.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.21-openssl", rpm:"go1.21-openssl~1.21.4.1~150000.1.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);