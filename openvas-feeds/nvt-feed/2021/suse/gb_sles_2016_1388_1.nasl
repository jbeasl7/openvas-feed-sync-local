# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.1388.1");
  script_cve_id("CVE-2013-3009", "CVE-2013-5456", "CVE-2016-0264", "CVE-2016-0363", "CVE-2016-0376", "CVE-2016-0686", "CVE-2016-0687", "CVE-2016-3422", "CVE-2016-3426", "CVE-2016-3427", "CVE-2016-3443", "CVE-2016-3449");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:06 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-27 19:23:19 +0000 (Thu, 27 Jun 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:1388-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:1388-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20161388-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'IBM Java 1.6.0' package(s) announced via the SUSE-SU-2016:1388-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This IBM Java 1.6.0 SR16 FP25 release fixes the following issues:
Security issues fixed:
CVE-2016-0264: buffer overflow vulnerability in the IBM JVM (bsc#977648)
CVE-2016-0363: insecure use of invoke method in CORBA component, incorrect CVE-2013-3009 fix (bsc#977650)
CVE-2016-0376: insecure deserialization in CORBA, incorrect CVE-2013-5456 fix (bsc#977646)
The following CVEs got also fixed during this update. (bsc#979252)
CVE-2016-3443, CVE-2016-0687, CVE-2016-0686, CVE-2016-3427,
CVE-2016-3449, CVE-2016-3422, CVE-2016-3426 Security Issues:
CVE-2016-0376 CVE-2016-0363 CVE-2016-0264 CVE-2016-3443 CVE-2016-0687 CVE-2016-0686 CVE-2016-3427 CVE-2016-3449 CVE-2016-3422 CVE-2016-3426");

  script_tag(name:"affected", value:"'IBM Java 1.6.0' package(s) on SUSE Linux Enterprise Server 10-SP4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-ibm", rpm:"java-1_6_0-ibm~1.6.0_sr16.25~0.11.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-ibm-32bit", rpm:"java-1_6_0-ibm-32bit~1.6.0_sr16.25~0.11.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-ibm-alsa", rpm:"java-1_6_0-ibm-alsa~1.6.0_sr16.25~0.11.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-ibm-alsa-32bit", rpm:"java-1_6_0-ibm-alsa-32bit~1.6.0_sr16.25~0.11.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-ibm-devel", rpm:"java-1_6_0-ibm-devel~1.6.0_sr16.25~0.11.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-ibm-devel-32bit", rpm:"java-1_6_0-ibm-devel-32bit~1.6.0_sr16.25~0.11.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-ibm-fonts", rpm:"java-1_6_0-ibm-fonts~1.6.0_sr16.25~0.11.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-ibm-jdbc", rpm:"java-1_6_0-ibm-jdbc~1.6.0_sr16.25~0.11.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-ibm-plugin", rpm:"java-1_6_0-ibm-plugin~1.6.0_sr16.25~0.11.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-ibm-plugin-32bit", rpm:"java-1_6_0-ibm-plugin-32bit~1.6.0_sr16.25~0.11.1", rls:"SLES10.0SP4"))) {
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
