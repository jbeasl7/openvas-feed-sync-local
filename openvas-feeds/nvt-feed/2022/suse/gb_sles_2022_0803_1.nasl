# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.0803.1");
  script_cve_id("CVE-2018-19787", "CVE-2020-27783", "CVE-2021-28957", "CVE-2021-43818");
  script_tag(name:"creation_date", value:"2022-03-11 04:13:20 +0000 (Fri, 11 Mar 2022)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-16 17:03:20 +0000 (Thu, 16 Dec 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:0803-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:0803-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20220803-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118088");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179534");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184177");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193752");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-March/010414.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-lxml' package(s) announced via the SUSE-SU-2022:0803-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-lxml fixes the following issues:

- CVE-2018-19787: Fixed XSS vulnerability via unescaped URL (bsc#1118088).
- CVE-2021-28957: Fixed XSS vulnerability ia HTML5 attributes unescaped (bsc#1184177).
- CVE-2021-43818: Fixed XSS vulnerability via script content in SVG images using data URIs (bnc#1193752).
- CVE-2020-27783: Fixed mutation XSS with improper parser use (bnc#1179534).");

  script_tag(name:"affected", value:"'python-lxml' package(s) on SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-lxml-debuginfo", rpm:"python-lxml-debuginfo~4.7.1~3.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-lxml-debugsource", rpm:"python-lxml-debugsource~4.7.1~3.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-lxml", rpm:"python3-lxml~4.7.1~3.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-lxml-debuginfo", rpm:"python3-lxml-debuginfo~4.7.1~3.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-lxml-devel", rpm:"python3-lxml-devel~4.7.1~3.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-lxml", rpm:"python2-lxml~4.7.1~3.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-lxml-debuginfo", rpm:"python2-lxml-debuginfo~4.7.1~3.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-lxml-devel", rpm:"python2-lxml-devel~4.7.1~3.7.1", rls:"SLES15.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"python-lxml-debuginfo", rpm:"python-lxml-debuginfo~4.7.1~3.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-lxml-debugsource", rpm:"python-lxml-debugsource~4.7.1~3.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-lxml", rpm:"python3-lxml~4.7.1~3.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-lxml-debuginfo", rpm:"python3-lxml-debuginfo~4.7.1~3.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-lxml-devel", rpm:"python3-lxml-devel~4.7.1~3.7.1", rls:"SLES15.0SP4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"python2-lxml", rpm:"python2-lxml~4.7.1~3.7.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-lxml-devel", rpm:"python2-lxml-devel~4.7.1~3.7.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-lxml", rpm:"python3-lxml~4.7.1~3.7.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-lxml-devel", rpm:"python3-lxml-devel~4.7.1~3.7.1", rls:"SLES15.0SP2"))) {
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
