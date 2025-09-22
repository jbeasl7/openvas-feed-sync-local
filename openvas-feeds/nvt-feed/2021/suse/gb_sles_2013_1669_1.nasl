# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2013.1669.1");
  script_cve_id("CVE-2013-3829", "CVE-2013-4002", "CVE-2013-4041", "CVE-2013-5372", "CVE-2013-5375", "CVE-2013-5774", "CVE-2013-5778", "CVE-2013-5780", "CVE-2013-5782", "CVE-2013-5783", "CVE-2013-5790", "CVE-2013-5797", "CVE-2013-5801", "CVE-2013-5802", "CVE-2013-5809", "CVE-2013-5814", "CVE-2013-5829", "CVE-2013-5840", "CVE-2013-5842", "CVE-2013-5843");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:23 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2013:1669-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP3|SLES10\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2013:1669-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2013/suse-su-20131669-1/");
  script_xref(name:"URL", value:"http://www.ibm.com/developerworks/java/jdk/alerts/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'IBM Java 5' package(s) announced via the SUSE-SU-2013:1669-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"IBM Java 5 SR16-FP4 has been released which fixes lots of bugs and security issues.

More information can be found on:
[link moved to references]

The following CVEs are fixed:
CVE-2013-4041,CVE-2013-5375,CVE-2013-5372,CVE-2013-5843,CVE-
2013-5830,CVE-2013-5829,CVE-2013-5842,CVE-2013-5782,CVE-2013
-5817,CVE-2013-5809,CVE-2013-5814,CVE-2013-5802,CVE-2013-580 4,CVE-2013-5783,CVE-2013-3829,CVE-2013-4002,CVE-2013-5774,CV E-2013-5825,CVE-2013-5840,CVE-2013-5801,CVE-2013-5778,CVE-20 13-5849,CVE-2013-5790,CVE-2013-5780,CVE-2013-5797,CVE-2013-5 803");

  script_tag(name:"affected", value:"'IBM Java 5' package(s) on SUSE Linux Enterprise Server 10-SP3, SUSE Linux Enterprise Server 10-SP4.");

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

if(release == "SLES10.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-ibm", rpm:"java-1_5_0-ibm~1.5.0_sr16.4~0.5.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-ibm-32bit", rpm:"java-1_5_0-ibm-32bit~1.5.0_sr16.4~0.5.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-ibm-alsa", rpm:"java-1_5_0-ibm-alsa~1.5.0_sr16.4~0.5.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-ibm-alsa-32bit", rpm:"java-1_5_0-ibm-alsa-32bit~1.5.0_sr16.4~0.5.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-ibm-devel", rpm:"java-1_5_0-ibm-devel~1.5.0_sr16.4~0.5.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-ibm-devel-32bit", rpm:"java-1_5_0-ibm-devel-32bit~1.5.0_sr16.4~0.5.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-ibm-fonts", rpm:"java-1_5_0-ibm-fonts~1.5.0_sr16.4~0.5.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-ibm-jdbc", rpm:"java-1_5_0-ibm-jdbc~1.5.0_sr16.4~0.5.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-ibm-plugin", rpm:"java-1_5_0-ibm-plugin~1.5.0_sr16.4~0.5.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES10.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-ibm", rpm:"java-1_5_0-ibm~1.5.0_sr16.4~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-ibm-32bit", rpm:"java-1_5_0-ibm-32bit~1.5.0_sr16.4~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-ibm-alsa", rpm:"java-1_5_0-ibm-alsa~1.5.0_sr16.4~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-ibm-alsa-32bit", rpm:"java-1_5_0-ibm-alsa-32bit~1.5.0_sr16.4~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-ibm-devel", rpm:"java-1_5_0-ibm-devel~1.5.0_sr16.4~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-ibm-devel-32bit", rpm:"java-1_5_0-ibm-devel-32bit~1.5.0_sr16.4~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-ibm-fonts", rpm:"java-1_5_0-ibm-fonts~1.5.0_sr16.4~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-ibm-jdbc", rpm:"java-1_5_0-ibm-jdbc~1.5.0_sr16.4~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-ibm-plugin", rpm:"java-1_5_0-ibm-plugin~1.5.0_sr16.4~0.5.1", rls:"SLES10.0SP4"))) {
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
