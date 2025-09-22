# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2024.3938.1");
  script_cve_id("CVE-2023-45288", "CVE-2023-45289", "CVE-2023-45290", "CVE-2024-24783", "CVE-2024-24784", "CVE-2024-24785", "CVE-2024-24787", "CVE-2024-24788", "CVE-2024-24789", "CVE-2024-24790", "CVE-2024-24791", "CVE-2024-34155", "CVE-2024-34156", "CVE-2024-34158");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-18 17:59:12 +0000 (Tue, 18 Jun 2024)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:3938-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3938-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243938-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218424");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219988");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220999");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221000");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221001");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221002");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221003");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224017");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224018");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225973");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225974");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227314");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230252");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230253");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230254");
  script_xref(name:"URL", value:"https://github.com/golang/go/wiki/Go-Release-Cycle");
  script_xref(name:"URL", value:"https://go-review.googlesource.com/c/go/+/554615");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-November/019791.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.22-openssl' package(s) announced via the SUSE-SU-2024:3938-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for go1.22-openssl fixes the following issues:

This update ships go1.22-openssl 1.22.7.1 (jsc#SLE-18320)

- Update to version 1.22.7.1 cut from the go1.22-fips-release
 branch at the revision tagged go1.22.7-1-openssl-fips.

 * Update to Go 1.22.7 (#229)

- go1.22.7 (released 2024-09-05) includes security fixes to the
 encoding/gob, go/build/constraint, and go/parser packages, as
 well as bug fixes to the fix command and the runtime.

 CVE-2024-34155 CVE-2024-34156 CVE-2024-34158:
 - go#69142 go#69138 bsc#1230252 security: fix CVE-2024-34155 go/parser: stack exhaustion in all Parse* functions (CVE-2024-34155)
 - go#69144 go#69139 bsc#1230253 security: fix CVE-2024-34156 encoding/gob: stack exhaustion in Decoder.Decode (CVE-2024-34156)
 - go#69148 go#69141 bsc#1230254 security: fix CVE-2024-34158 go/build/constraint: stack exhaustion in Parse (CVE-2024-34158)
 - go#68811 os: TestChtimes failures
 - go#68825 cmd/fix: fails to run on modules whose go directive value is in '1.n.m' format introduced in Go 1.21.0
 - go#68972 cmd/cgo: aix c-archive corrupting stack

- go1.22.6 (released 2024-08-06) includes fixes to the go command,
 the compiler, the linker, the trace command, the covdata command,
 and the bytes, go/types, and os/exec packages.

 * go#68594 cmd/compile: internal compiler error with zero-size types
 * go#68546 cmd/trace/v2: pprof profiles always empty
 * go#68492 cmd/covdata: too many open files due to defer f.Close() in for loop
 * go#68475 bytes: IndexByte can return -4294967295 when memory usage is above 2^31 on js/wasm
 * go#68370 go/types: assertion failure in recent range statement checking logic
 * go#68331 os/exec: modifications to Path ignored when *Cmd is created using Command with an absolute path on Windows
 * go#68230 cmd/compile: inconsistent integer arithmetic result on Go 1.22+arm64 with/without -race
 * go#68222 cmd/go: list with -export and -covermode=atomic fails to build
 * go#68198 cmd/link: issues with Xcode 16 beta

- Update to version 1.22.5.3 cut from the go1.22-fips-release
 branch at the revision tagged go1.22.5-3-openssl-fips.

 * Only load openssl if fips == '1'
 Avoid loading openssl whenever GOLANG_FIPS is not 1.
 Previously only an unset variable would cause the library load
 to be skipped, but users may also expect to be able to set eg.
 GOLANG_FIPS=0 in environments without openssl.

- Update to version 1.22.5.2 cut from the go1.22-fips-release
 branch at the revision tagged go1.22.5-2-openssl-fips.

 * Only load OpenSSL when in FIPS mode

- Update to version 1.22.5.1 cut from the go1.22-fips-release
 branch at the revision tagged go1.22.5-1-openssl-fips.

 * Update to go1.22.5

- go1.22.5 (released 2024-07-02) includes security fixes to the
 net/http package, as well as bug fixes to the compiler, cgo, the
 go command, the linker, the runtime, and the crypto/tls,
 go/types, net, net/http, and os/exec packages.

 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'go1.22-openssl' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"go1.22-openssl", rpm:"go1.22-openssl~1.22.7.1~150600.13.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.22-openssl-doc", rpm:"go1.22-openssl-doc~1.22.7.1~150600.13.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.22-openssl-race", rpm:"go1.22-openssl-race~1.22.7.1~150600.13.3.1", rls:"openSUSELeap15.6"))) {
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
