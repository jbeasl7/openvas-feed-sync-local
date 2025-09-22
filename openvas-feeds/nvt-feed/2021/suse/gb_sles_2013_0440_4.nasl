# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2013.0440.4");
  script_cve_id("CVE-2013-0409", "CVE-2013-0424", "CVE-2013-0425", "CVE-2013-0426", "CVE-2013-0427", "CVE-2013-0428", "CVE-2013-0432", "CVE-2013-0433", "CVE-2013-0434", "CVE-2013-0440", "CVE-2013-0442", "CVE-2013-0443", "CVE-2013-0445", "CVE-2013-1476", "CVE-2013-1478", "CVE-2013-1480", "CVE-2013-1481", "CVE-2013-1486");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:25 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2013:0440-4)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2013:0440-4");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2013/suse-su-20130440-4/");
  script_xref(name:"URL", value:"http://www.ibm.com/developerworks/java/jdk/alerts/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Java' package(s) announced via the SUSE-SU-2013:0440-4 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"IBM Java 5 has been updated to SR16 which fixes various critical security issues and bugs.

Please see the IBM JDK Alert page for more information:

[link moved to references]

Security issues fixed:

CVE-2013-1486, CVE-2013-1478, CVE-2013-0445, CVE-2013-1480,
CVE-2013-1476, CVE-2013-0442, CVE-2013-0425,
CVE-2013-0426, CVE-2013-0428, CVE-2013-1481,
CVE-2013-0432, CVE-2013-0434, CVE-2013-0409, CVE-2013-0427,
CVE-2013-0433, CVE-2013-0424, CVE-2013-0440, CVE-2013-0443.");

  script_tag(name:"affected", value:"'Java' package(s) on SUSE Linux Enterprise Desktop 10-SP4, SUSE Linux Enterprise Java 10-SP4, SUSE Linux Enterprise Server 10-SP4.");

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

if(release == "SLES10.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-ibm", rpm:"java-1_5_0-ibm~1.5.0_sr16.0~0.6.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-ibm-32bit", rpm:"java-1_5_0-ibm-32bit~1.5.0_sr16.0~0.6.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-ibm-64bit", rpm:"java-1_5_0-ibm-64bit~1.5.0_sr16.0~0.6.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-ibm-alsa", rpm:"java-1_5_0-ibm-alsa~1.5.0_sr16.0~0.6.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-ibm-alsa-32bit", rpm:"java-1_5_0-ibm-alsa-32bit~1.5.0_sr16.0~0.6.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-ibm-devel", rpm:"java-1_5_0-ibm-devel~1.5.0_sr16.0~0.6.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-ibm-devel-32bit", rpm:"java-1_5_0-ibm-devel-32bit~1.5.0_sr16.0~0.6.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-ibm-fonts", rpm:"java-1_5_0-ibm-fonts~1.5.0_sr16.0~0.6.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-ibm-jdbc", rpm:"java-1_5_0-ibm-jdbc~1.5.0_sr16.0~0.6.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-ibm-plugin", rpm:"java-1_5_0-ibm-plugin~1.5.0_sr16.0~0.6.1", rls:"SLES10.0SP4"))) {
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
