# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.01878.1");
  script_cve_id("CVE-2025-23165", "CVE-2025-23166");
  script_tag(name:"creation_date", value:"2025-06-13 04:10:49 +0000 (Fri, 13 Jun 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:01878-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:01878-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202501878-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239949");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241050");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243217");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243218");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-June/040230.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs22' package(s) announced via the SUSE-SU-2025:01878-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nodejs22 fixes the following issues:

Update to version 22.15.1.

Security issues fixed:

- CVE-2025-23166: remotely triggerable process crash due to improper error handling in async cryptographic operations
 (bsc#1243218).
- CVE-2025-23165: memory leak and unbounded memory growth due to corrupted pointer in
 `node::fs::ReadFileUtf8(const FunctionCallbackInfo<Value>& args)` when `args[0]` is a string (bsc#1243217).

Other changes and issues fixed:

- Changes from version 22.15.0

 * dns: add TLSA record query and parsing
 * assert: improve partialDeepStrictEqual
 * process: add execve
 * tls: implement tls.getCACertificates()
 * v8: add v8.getCppHeapStatistics() method

- Changes from version 22.14.0

 * fs: allow exclude option in globs to accept glob patterns
 * lib: add typescript support to STDIN eval
 * module: add ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX
 * module: add findPackageJSON util
 * process: add process.ref() and process.unref() methods
 * sqlite: support TypedArray and DataView in StatementSync
 * src: add --disable-sigusr1 to prevent signal i/o thread
 * src,worker: add isInternalWorker
 * test_runner: add TestContext.prototype.waitFor()
 * test_runner: add t.assert.fileSnapshot()
 * test_runner: add assert.register() API
 * worker: add eval ts input

- Build with PIE (bsc#1239949).
- Fix builds with OpenSSL 3.5.0 (bsc#1241050).");

  script_tag(name:"affected", value:"'nodejs22' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"corepack22", rpm:"corepack22~22.15.1~150600.13.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs22", rpm:"nodejs22~22.15.1~150600.13.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs22-devel", rpm:"nodejs22-devel~22.15.1~150600.13.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs22-docs", rpm:"nodejs22-docs~22.15.1~150600.13.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm22", rpm:"npm22~22.15.1~150600.13.9.1", rls:"openSUSELeap15.6"))) {
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
