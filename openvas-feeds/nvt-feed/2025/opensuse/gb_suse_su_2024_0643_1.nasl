# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2024.0643.1");
  script_cve_id("CVE-2023-46809", "CVE-2024-21890", "CVE-2024-21891", "CVE-2024-21892", "CVE-2024-21896", "CVE-2024-22017", "CVE-2024-22019", "CVE-2024-22025", "CVE-2024-24758", "CVE-2024-24806");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-02 20:09:59 +0000 (Wed, 02 Apr 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:0643-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0643-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240643-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219152");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219724");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219992");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219993");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219994");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219997");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219998");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219999");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220014");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220017");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-February/018059.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs20' package(s) announced via the SUSE-SU-2024:0643-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nodejs20 fixes the following issues:

Update to 20.11.1: (security updates)

* CVE-2024-21892: Code injection and privilege escalation through Linux capabilities (bsc#1219992).
* CVE-2024-22019: http: Reading unprocessed HTTP request with unbounded chunk extension allows DoS attacks (bsc#1219993).
* CVE-2024-21896: Path traversal by monkey-patching Buffer internals (bsc#1219994).j
* CVE-2024-22017: setuid() does not drop all privileges due to io_uring (bsc#1219995).
* CVE-2023-46809: Node.js is vulnerable to the Marvin Attack (timing variant of the Bleichenbacher attack against PKCS#1 v1.5 padding) (bsc#1219997).
* CVE-2024-21891: Multiple permission model bypasses due to improper path traversal sequence sanitization (bsc#1219998).
* CVE-2024-21890: Improper handling of wildcards in --allow-fs-read and --allow-fs-write (bsc#1219999).
* CVE-2024-22025: Denial of Service by resource exhaustion in fetch() brotli decoding (bsc#1220014).
* CVE-2024-24758: undici version 5.28.3 (bsc#1220017).
* CVE-2024-24806: libuv version 1.48.0 (bsc#1219724).

Update to 20.11.0:

* esm: add import.meta.dirname and import.meta.filename
* fs: add c++ fast path for writeFileSync utf8
* module: remove useCustomLoadersIfPresent flag
* module: bootstrap module loaders in shadow realm
* src: add --disable-warning option
* src: create per isolate proxy env template
* src: make process binding data weak
* stream: use Array for Readable buffer
* stream: optimize creation
* test_runner: adds built in lcov reporter
* test_runner: add Date to the supported mock APIs
* test_runner, cli: add --test-timeout flag

Update to 20.10.0:

* --experimental-default-type flag to flip module defaults
* The new flag --experimental-detect-module can be used to automatically run ES modules when their syntax can be detected.
* Added flush option in file system functions for fs.writeFile functions
* Added experimental WebSocket client
* vm: fix V8 compilation cache support for vm.Script. This fixes performance regression since v16.x when support for importModuleDynamically was added to vm.Script");

  script_tag(name:"affected", value:"'nodejs20' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"corepack20", rpm:"corepack20~20.11.1~150500.11.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs20", rpm:"nodejs20~20.11.1~150500.11.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs20-devel", rpm:"nodejs20-devel~20.11.1~150500.11.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs20-docs", rpm:"nodejs20-docs~20.11.1~150500.11.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm20", rpm:"npm20~20.11.1~150500.11.6.1", rls:"openSUSELeap15.5"))) {
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
