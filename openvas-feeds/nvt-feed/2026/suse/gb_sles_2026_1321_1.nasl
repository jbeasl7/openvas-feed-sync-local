# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.1321.1");
  script_cve_id("CVE-2026-27140", "CVE-2026-27143", "CVE-2026-27144", "CVE-2026-32280", "CVE-2026-32281", "CVE-2026-32282", "CVE-2026-32283", "CVE-2026-32288", "CVE-2026-32289");
  script_tag(name:"creation_date", value:"2026-04-16 05:02:43 +0000 (Thu, 16 Apr 2026)");
  script_version("2026-04-16T06:18:46+0000");
  script_tag(name:"last_modification", value:"2026-04-16 06:18:46 +0000 (Thu, 16 Apr 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:1321-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4|SLES15\.0SP5|SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:1321-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20261321-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244485");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1261653");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1261654");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1261655");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1261656");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1261657");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1261658");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1261659");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1261660");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1261661");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2026-April/045526.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.25' package(s) announced via the SUSE-SU-2026:1321-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for go1.25 fixes the following issues:

- Update to go1.25.9 (bsc#1244485).
- CVE-2026-27140: cmd/go: trust layer bypass when using cgo and SWIG (bsc#1261653).
- CVE-2026-27143: cmd/compile: possible memory corruption after bound check elimination (bsc#1261654).
- CVE-2026-27144: cmd/compile: no-op interface conversion bypasses overlap checking (bsc#1261655).
- CVE-2026-32280: crypto/x509: unexpected work during chain building (bsc#1261656).
- CVE-2026-32281: crypto/x509: inefficient policy validation (bsc#1261657).
- CVE-2026-32282: os: Root.Chmod can follow symlinks out of the root on Linux (bsc#1261658).
- CVE-2026-32283: crypto/tls: multiple key update handshake messages can cause connection to deadlock (bsc#1261659).
- CVE-2026-32288: archive/tar: unbounded allocation when parsing old format GNU sparse map (bsc#1261660).
- CVE-2026-32289: html/template: JS template literal context incorrectly tracked (bsc#1261661).");

  script_tag(name:"affected", value:"'go1.25' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server 15-SP6, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP6.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"go1.25", rpm:"go1.25~1.25.9~150000.1.35.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.25-doc", rpm:"go1.25-doc~1.25.9~150000.1.35.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.25-race", rpm:"go1.25-race~1.25.9~150000.1.35.1", rls:"SLES15.0SP4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"go1.25", rpm:"go1.25~1.25.9~150000.1.35.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.25-doc", rpm:"go1.25-doc~1.25.9~150000.1.35.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.25-race", rpm:"go1.25-race~1.25.9~150000.1.35.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"go1.25", rpm:"go1.25~1.25.9~150000.1.35.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.25-doc", rpm:"go1.25-doc~1.25.9~150000.1.35.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.25-race", rpm:"go1.25-race~1.25.9~150000.1.35.1", rls:"SLES15.0SP6"))) {
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
