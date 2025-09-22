# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2024.3937.1");
  script_cve_id("CVE-2024-34155", "CVE-2024-34156", "CVE-2024-34158");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:3937-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3937-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243937-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229122");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230252");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230253");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230254");
  script_xref(name:"URL", value:"https://github.com/golang/go/wiki/Go-Release-Cycle");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-November/019792.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.23-openssl' package(s) announced via the SUSE-SU-2024:3937-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for go1.23-openssl fixes the following issues:

This update ships go1.23-openssl version 1.23.2.2. (jsc#SLE-18320)

- go1.23.2 (released 2024-10-01) includes fixes to the compiler,
 cgo, the runtime, and the maps, os, os/exec, time, and unique
 packages.

 * go#69119 os: double close pidfd if caller uses pidfd updated by os.StartProcess
 * go#69156 maps: segmentation violation in maps.Clone
 * go#69219 cmd/cgo: alignment issue with int128 inside of a struct
 * go#69240 unique: fatal error: found pointer to free object
 * go#69333 runtime,time: timer.Stop returns false even when no value is read from the channel
 * go#69383 unique: large string still referenced, after interning only a small substring
 * go#69402 os/exec: resource leak on exec failure
 * go#69511 cmd/compile: mysterious crashes and non-determinism with range over func

- Update to version 1.23.1.1 cut from the go1.23-fips-release
 branch at the revision tagged go1.23.1-1-openssl-fips.

 * Update to Go 1.23.1 (#238)

- go1.23.1 (released 2024-09-05) includes security fixes to the
 encoding/gob, go/build/constraint, and go/parser packages, as
 well as bug fixes to the compiler, the go command, the runtime,
 and the database/sql, go/types, os, runtime/trace, and unique
 packages.

 CVE-2024-34155 CVE-2024-34156 CVE-2024-34158:

 - go#69143 go#69138 bsc#1230252 security: fix CVE-2024-34155 go/parser: stack exhaustion in all Parse* functions
 - go#69145 go#69139 bsc#1230253 security: fix CVE-2024-34156 encoding/gob: stack exhaustion in Decoder.Decode
 - go#69149 go#69141 bsc#1230254 security: fix CVE-2024-34158 go/build/constraint: stack exhaustion in Parse
 - go#68812 os: TestChtimes failures
 - go#68894 go/types: 'under' panics on Alias type
 - go#68905 cmd/compile: error in Go 1.23.0 with generics, type aliases and indexing
 - go#68907 os: CopyFS overwrites existing file in destination.
 - go#68973 cmd/cgo: aix c-archive corrupting stack
 - go#68992 unique: panic when calling unique.Make with string casted as any
 - go#68994 cmd/go: any invocation creates read-only telemetry configuration file under GOMODCACHE
 - go#68995 cmd/go: multi-arch build via qemu fails to exec go binary
 - go#69041 database/sql: panic in database/sql.(*connRequestSet).deleteIndex
 - go#69087 runtime/trace: crash during traceAdvance when collecting call stack for cgo-calling goroutine
 - go#69094 cmd/go: breaking change in 1.23rc2 with version constraints in GOPATH mode

- go1.23 (released 2024-08-13) is a major release of Go.
 go1.23.x minor releases will be provided through August 2025.
 [link moved to references]
 go1.23 arrives six months after go1.22. Most of its changes are
 in the implementation of the toolchain, runtime, and libraries.
 As always, the release maintains the Go 1 promise of
 compatibility. We expect almost all Go programs to continue to
 compile and run as before.

 * Language change: Go 1.23 makes ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'go1.23-openssl' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"go1.23-openssl", rpm:"go1.23-openssl~1.23.2.2~150600.13.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.23-openssl-doc", rpm:"go1.23-openssl-doc~1.23.2.2~150600.13.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.23-openssl-race", rpm:"go1.23-openssl-race~1.23.2.2~150600.13.3.1", rls:"openSUSELeap15.6"))) {
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
