# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.2562.1");
  script_cve_id("CVE-2020-14039", "CVE-2020-15586", "CVE-2020-16845");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:55 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-11 16:11:14 +0000 (Tue, 11 Aug 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:2562-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:2562-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20202562-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.14' package(s) announced via the SUSE-SU-2020:2562-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for go1.14 fixes the following issues:

go1.14 was updated to version 1.14.7

CVE-2020-16845: dUvarint and ReadVarint can read an unlimited number of
 bytes from invalid inputs (bsc#1174977).

go1.14.6 (released 2020-07-16) includes fixes to the go command, the
 compiler, the linker, vet, and the database/sql, encoding/json,
 net/http, reflect, and testing packages. Refs bsc#1164903 go1.14 release
 tracking Refs bsc#1174153 bsc#1174191
 * go#39991 runtime: missing deferreturn on linux/ppc64le
 * go#39920 net/http: panic on misformed If-None-Match Header with
 http.ServeContent
 * go#39849 cmd/compile: internal compile error when using sync.Pool:
 mismatched zero/store sizes
 * go#39824 cmd/go: TestBuildIDContainsArchModeEnv/386 fails on linux/386
 in Go 1.14 and 1.13, not 1.15
 * go#39698 reflect: panic from malloc after MakeFunc function returns
 value that is also stored globally
 * go#39636 reflect: DeepEqual can return true for values that are not
 equal
 * go#39585 encoding/json: incorrect object key unmarshaling when using
 custom TextUnmarshaler as Key with string va lues
 * go#39562 cmd/compile/internal/ssa: TestNexting/dlv-dbg-hist failing on
 linux-386-longtest builder because it trie s to use an older version
 of dlv which only supports linux/amd64
 * go#39308 testing: streaming output loses parallel subtest associations
 * go#39288 cmd/vet: update for new number formats
 * go#39101 database/sql: context cancellation allows statements to
 execute after rollback
 * go#38030 doc: BuildNameToCertificate deprecated in go 1.14 not
 mentioned in the release notes
 * go#40212 net/http: Expect 100-continue panics in httputil.ReverseProxy
 bsc#1174153 CVE-2020-15586
 * go#40210 crypto/x509: Certificate.Verify method seemingly ignoring EKU
 requirements on Windows bsc#1174191 CVE-2020-14039 (Windows only)

Add patch to ensure /etc/hosts is used if /etc/nsswitch.conf is not
 present bsc#1172868 gh#golang/go#35305");

  script_tag(name:"affected", value:"'go1.14' package(s) on SUSE Linux Enterprise Module for Development Tools 15-SP1, SUSE Linux Enterprise Module for Development Tools 15-SP2.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"go1.14", rpm:"go1.14~1.14.7~1.15.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.14-doc", rpm:"go1.14-doc~1.14.7~1.15.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"go1.14", rpm:"go1.14~1.14.7~1.15.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.14-doc", rpm:"go1.14-doc~1.14.7~1.15.1", rls:"SLES15.0SP2"))) {
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
