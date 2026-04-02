# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2026.0876.1");
  script_cve_id("CVE-2026-25679", "CVE-2026-27137", "CVE-2026-27138", "CVE-2026-27139", "CVE-2026-27142");
  script_tag(name:"creation_date", value:"2026-03-16 04:54:03 +0000 (Mon, 16 Mar 2026)");
  script_version("2026-03-16T06:13:25+0000");
  script_tag(name:"last_modification", value:"2026-03-16 06:13:25 +0000 (Mon, 16 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2026:0876-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0876-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260876-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255111");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259264");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259265");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259266");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259267");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259268");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024673.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.26' package(s) announced via the SUSE-SU-2026:0876-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for go1.26 fixes the following issues:

Update to go1.26.1 (bsc#1255111):

- CVE-2026-25679: net/url: reject IPv6 literal not at start of host (bsc#1259264).
- CVE-2026-27137: crypto/x509: incorrect enforcement of email constraints (bsc#1259266).
- CVE-2026-27138: crypto/x509: panic in name constraint checking for malformed certificates (bsc#1259267).
- CVE-2026-27139: os: FileInfo can escape from a Root (bsc#1259268).
- CVE-2026-27142: html/template: URLs in meta content attribute actions are not escaped (bsc#1259265).

Changelog:

* go#77252 cmd/compile: miscompile of global array initialization
* go#77407 os: Go 1.25.x regression on RemoveAll for windows
* go#77474 cmd/go: CGO compilation fails after upgrading from Go 1.25.5 to 1.25.6 due to --define-variable flag in
 pkg-config
* go#77529 cmd/fix, x/tools/go/analysis/passes/modernize: stringscut: OOB panic in indexArgValid analyzing
 'buf.Bytes()' call
* go#77532 net/smtp: expiry date of localhostCert for testing is too short
* go#77536 cmd/compile: internal compiler error: 'main.func1': not lowered: v15, Load STRUCT PTR SSA
* go#77618 strings: HasSuffix doesn't work correctly for multibyte runes in go 1.26
* go#77623 cmd/compile: internal compiler error on : 'tried to free an already free register' with generic function
 and type >= 192 bytes
* go#77624 cmd/fix, x/tools/go/analysis/passes/modernize: stringsbuilder breaks code when combining two
 strings.Builders
* go#77680 cmd/link: TestFlagW/-w_-linkmode=external fails on illumos
* go#77766 cmd/fix,x/tools/go/analysis/passes/modernize: rangeint uses target platform's type in the range expression,
 breaking other platforms
* go#77780 reflect: breaking change for reflect.Value.Interface behaviour
* go#77786 cmd/compile: rewriteFixedLoad does not properly sign extend AuxInt
* go#77803 cmd/fix,x/tools/go/analysis/passes/modernize: reflect.TypeOf(nil) transformed into
 reflect.TypeFor[untyped nil]()
* go#77804 cmd/fix,x/tools/go/analysis/passes/modernize: minmax breaks select statements
* go#77805 cmd/fix, x/tools/go/analysis/passes/modernize: waitgroup leads to a compilation error
* go#77807 cmd/fix,x/tools/go/analysis/passes/modernize: stringsbuilder ignores variables if they are used multiple
 times
* go#77849 cmd/fix,x/tools/go/analysis/passes/modernize: stringscut rewrite changes behavior
* go#77860 cmd/go: change go mod init default go directive back to 1.N
* go#77899 cmd/fix, x/tools/go/analysis/passes/modernize: bad rangeint rewriting
* go#77904 x/tools/go/analysis/passes/modernize: stringsbuilder breaks code when GenDecl is a block declaration");

  script_tag(name:"affected", value:"'go1.26' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"go1.26", rpm:"go1.26~1.26.1~150000.1.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.26-doc", rpm:"go1.26-doc~1.26.1~150000.1.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.26-race", rpm:"go1.26-race~1.26.1~150000.1.6.1", rls:"openSUSELeap15.6"))) {
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
