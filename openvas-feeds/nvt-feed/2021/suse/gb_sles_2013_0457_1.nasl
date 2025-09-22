# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2013.0457.1");
  script_cve_id("CVE-2012-6093", "CVE-2013-0254");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:25 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2013:0457-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2013:0457-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2013/suse-su-20130457-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libqt4' package(s) announced via the SUSE-SU-2013:0457-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"libqt4 has been updated to fix several security issues.

 * An information disclosure via QSharedMemory was fixed which allowed local attackers to read information (e.g.
bitmap content) from the attacked user (CVE-2013-0254).
 * openssl-incompatibility-fix.diff: Fix wrong error reporting when using a binary incompatible version of openSSL (bnc#797006, CVE-2012-6093)
 * Various compromised SSL root certificates were blacklisted.

Also a non-security bugfix has been applied:

 * Add fix for qdbusviewer not matching args (bnc#784197)

Security Issue reference:

 * CVE-2013-0254
>");

  script_tag(name:"affected", value:"'libqt4' package(s) on SUSE Linux Enterprise Desktop 11-SP2, SUSE Linux Enterprise Server 11-SP2, SUSE Linux Enterprise Software Development Kit 11-SP2.");

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

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libQtWebKit4-32bit", rpm:"libQtWebKit4-32bit~4.6.3~5.20.23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQtWebKit4", rpm:"libQtWebKit4~4.6.3~5.20.23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQtWebKit4-x86", rpm:"libQtWebKit4-x86~4.6.3~5.20.23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-32bit", rpm:"libqt4-32bit~4.6.3~5.20.23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4", rpm:"libqt4~4.6.3~5.20.23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-qt3support-32bit", rpm:"libqt4-qt3support-32bit~4.6.3~5.20.23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-qt3support", rpm:"libqt4-qt3support~4.6.3~5.20.23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-qt3support-x86", rpm:"libqt4-qt3support-x86~4.6.3~5.20.23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql-32bit", rpm:"libqt4-sql-32bit~4.6.3~5.20.23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql", rpm:"libqt4-sql~4.6.3~5.20.23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql-mysql", rpm:"libqt4-sql-mysql~4.6.3~5.20.23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql-sqlite", rpm:"libqt4-sql-sqlite~4.6.3~5.20.23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql-x86", rpm:"libqt4-sql-x86~4.6.3~5.20.23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-x11-32bit", rpm:"libqt4-x11-32bit~4.6.3~5.20.23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-x11", rpm:"libqt4-x11~4.6.3~5.20.23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-x11-x86", rpm:"libqt4-x11-x86~4.6.3~5.20.23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-x86", rpm:"libqt4-x86~4.6.3~5.20.23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-x11-tools", rpm:"qt4-x11-tools~4.6.3~5.20.23.1", rls:"SLES11.0SP2"))) {
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
