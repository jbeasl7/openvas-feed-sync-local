# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0376.1");
  script_cve_id("CVE-2014-3065", "CVE-2014-3566", "CVE-2014-4209", "CVE-2014-4218", "CVE-2014-4219", "CVE-2014-4244", "CVE-2014-4252", "CVE-2014-4262", "CVE-2014-4263", "CVE-2014-4268", "CVE-2014-6457", "CVE-2014-6502", "CVE-2014-6506", "CVE-2014-6511", "CVE-2014-6512", "CVE-2014-6531", "CVE-2014-6558", "CVE-2014-8891", "CVE-2014-8892");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:14 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2015-03-09 14:02:17 +0000 (Mon, 09 Mar 2015)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0376-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0376-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150376-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_5_0-ibm' package(s) announced via the SUSE-SU-2015:0376-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"java-1_5_0-ibm has been updated to fix 19 security issues:

 * CVE-2014-8891: Unspecified vulnerability (bnc#916266).
 * CVE-2014-8892: Unspecified vulnerability (bnc#916265).
 * CVE-2014-3065: Unspecified vulnerability in IBM Java Runtime
 Environment (JRE) 7 R1 before SR2 (7.1.2.0), 7 before SR8 (7.0.8.0),
 6 R1 before SR8 FP2 (6.1.8.2), 6 before SR16 FP2 (6.0.16.2), and
 before SR16 FP8 (5.0.16.8) allows local users to execute arbitrary
 code via vectors related to the shared classes cache (bnc#904889).
 * CVE-2014-3566: The SSL protocol 3.0, as used in OpenSSL through
 1.0.1i and other products, uses nondeterministic CBC padding, which
 makes it easier for man-in-the-middle attackers to obtain cleartext
 data via a padding-oracle attack, aka the 'POODLE' issue
 (bnc#901223).
 * CVE-2014-6506: Unspecified vulnerability in Oracle Java SE 5.0u71,
 6u81, 7u67, and 8u20, and Java SE Embedded 7u60, allows remote
 attackers to affect confidentiality, integrity, and availability via
 unknown vectors related to Libraries (bnc#901239).
 * CVE-2014-6511: Unspecified vulnerability in Oracle Java SE 5.0u71,
 6u81, 7u67, and 8u20 allows remote attackers to affect
 confidentiality via unknown vectors related to 2D (bnc#901239).
 * CVE-2014-6531: Unspecified vulnerability in Oracle Java SE 5.0u71,
 6u81, 7u67, and 8u20, and Java SE Embedded 7u60, allows remote
 attackers to affect confidentiality via unknown vectors related to
 Libraries (bnc#901239).
 * CVE-2014-6512: Unspecified vulnerability in Oracle Java SE 5.0u71,
 6u81, 7u67, and 8u20, Java SE Embedded 7u60, and JRockit R27.8.3 and
 R28.3.3 allows remote attackers to affect integrity via unknown
 vectors related to Libraries (bnc#901239).
 * CVE-2014-6457: Unspecified vulnerability in Oracle Java SE 5.0u71,
 6u81, 7u67, and 8u20, Java SE Embedded 7u60, and JRockit R27.8.3,
 and R28.3.3 allows remote attackers to affect confidentiality and
 integrity via vectors related to JSSE (bnc#901239).
 * CVE-2014-6502: Unspecified vulnerability in Oracle Java SE 5.0u71,
 6u81, 7u67, and 8u20, and Java SE Embedded 7u60, allows remote
 attackers to affect integrity via unknown vectors related to
 Libraries (bnc#901239).
 * CVE-2014-6558: Unspecified vulnerability in Oracle Java SE 5.0u71,
 6u81, 7u67, and 8u20, Java SE Embedded 7u60, and JRockit R27.8.3 and
 JRockit R28.3.3 allows remote attackers to affect integrity via
 unknown vectors related to Security (bnc#901239).
 * CVE-2014-4262: Unspecified vulnerability in Oracle Java SE 5.0u65,
 6u75, 7u60, and 8u5 allows remote attackers to affect
 confidentiality, integrity, and availability via unknown vectors
 related to Libraries (bnc#891699).
 * CVE-2014-4219: Unspecified vulnerability in Oracle Java SE 6u75,
 7u60, and 8u5 allows remote attackers to affect confidentiality,
 integrity, and availability via unknown vectors related to Hotspot
 (bnc#891699).
 * CVE-2014-4209: Unspecified ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'java-1_5_0-ibm' package(s) on SUSE Linux Enterprise Server 10-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-ibm", rpm:"java-1_5_0-ibm~1.5.0_sr16.9~0.6.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-ibm-32bit", rpm:"java-1_5_0-ibm-32bit~1.5.0_sr16.9~0.6.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-ibm-alsa", rpm:"java-1_5_0-ibm-alsa~1.5.0_sr16.9~0.6.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-ibm-alsa-32bit", rpm:"java-1_5_0-ibm-alsa-32bit~1.5.0_sr16.9~0.6.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-ibm-devel", rpm:"java-1_5_0-ibm-devel~1.5.0_sr16.9~0.6.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-ibm-devel-32bit", rpm:"java-1_5_0-ibm-devel-32bit~1.5.0_sr16.9~0.6.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-ibm-fonts", rpm:"java-1_5_0-ibm-fonts~1.5.0_sr16.9~0.6.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-ibm-jdbc", rpm:"java-1_5_0-ibm-jdbc~1.5.0_sr16.9~0.6.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-ibm-plugin", rpm:"java-1_5_0-ibm-plugin~1.5.0_sr16.9~0.6.1", rls:"SLES10.0SP4"))) {
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
