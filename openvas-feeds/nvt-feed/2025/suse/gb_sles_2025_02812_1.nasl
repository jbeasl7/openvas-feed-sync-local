# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.02812.1");
  script_cve_id("CVE-2025-4674", "CVE-2025-47906", "CVE-2025-47907");
  script_tag(name:"creation_date", value:"2025-08-18 04:22:46 +0000 (Mon, 18 Aug 2025)");
  script_version("2025-08-18T05:42:33+0000");
  script_tag(name:"last_modification", value:"2025-08-18 05:42:33 +0000 (Mon, 18 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:02812-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4|SLES15\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02812-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502812-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229122");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246118");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247719");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247720");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247816");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-August/041227.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.23-openssl' package(s) announced via the SUSE-SU-2025:02812-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for go1.23-openssl fixes the following issues:

Updated to go1.23.12 (released 2025-08-06) (bsc#1229122):
 - CVE-2025-4674: Fixed unexpected command execution in untrusted VCS repositories in cmd/go (bsc#1246118)
 - CVE-2025-47906: Fixed incorrect expansion of '', '.' and '..' in some PATH configurations in LookPath in osc/exec (bsc#1247719)
 - CVE-2025-47907: Fixed incorrect results returned from Rows.Scan in database/sql (bsc#1247720)

Updated to version 1.23.12 cut from the go1.23-fips-release branch at the revision tagged go1.23.12-1-openssl-fips (jsc#SLE-18320)
 - Fix HKDF-Extract The latest OpenSSL in c9s/c10s requires nil
 salt to be passed as a hash length buffer of zeros.

Other fixes:
 - runtime: use-after-free of allpSnapshot in findRunnable
 - runtime: segfaults in runtime.(*unwinder).next
 - cmd/go: TestScript/build_trimpath_cgo fails to decode dwarf on release-branch.go1.23
 - cmd/cgo/internal/testsanitizers: failures with signal: segmentation fault or exit status 66
 - runtime: bad frame pointer during panic during duffcopy
 - runtime: heap mspan limit is set too late, causing data race between span allocation and conservative scanning
 - internal/trace: stress tests triggering suspected deadlock in tracer
 - runtime/pprof: crash 'cannot read stack of running goroutine' in goroutine profile
 - cmd/link: duplicated definition of symbol github.com/ebitengine/purego.syscall15XABI0 when running with ASAN");

  script_tag(name:"affected", value:"'go1.23-openssl' package(s) on SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"go1.23-openssl", rpm:"go1.23-openssl~1.23.12~150000.1.18.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.23-openssl-doc", rpm:"go1.23-openssl-doc~1.23.12~150000.1.18.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.23-openssl-race", rpm:"go1.23-openssl-race~1.23.12~150000.1.18.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"go1.23-openssl", rpm:"go1.23-openssl~1.23.12~150000.1.18.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.23-openssl-doc", rpm:"go1.23-openssl-doc~1.23.12~150000.1.18.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.23-openssl-race", rpm:"go1.23-openssl-race~1.23.12~150000.1.18.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"go1.23-openssl", rpm:"go1.23-openssl~1.23.12~150000.1.18.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.23-openssl-doc", rpm:"go1.23-openssl-doc~1.23.12~150000.1.18.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.23-openssl-race", rpm:"go1.23-openssl-race~1.23.12~150000.1.18.1", rls:"SLES15.0SP5"))) {
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
