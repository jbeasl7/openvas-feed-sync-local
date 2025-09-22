# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.1329.1");
  script_cve_id("CVE-2015-1931", "CVE-2015-2590", "CVE-2015-2601", "CVE-2015-2613", "CVE-2015-2619", "CVE-2015-2621", "CVE-2015-2625", "CVE-2015-2632", "CVE-2015-2637", "CVE-2015-2638", "CVE-2015-2664", "CVE-2015-2808", "CVE-2015-4000", "CVE-2015-4729", "CVE-2015-4731", "CVE-2015-4732", "CVE-2015-4733", "CVE-2015-4748", "CVE-2015-4749", "CVE-2015-4760");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:11 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:43:11 +0000 (Tue, 16 Jul 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:1329-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:1329-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20151329-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935540");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/938895");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-July/001519.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_7_1-ibm' package(s) announced via the SUSE-SU-2015:1329-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"IBM Java was updated to 7.1-3.10 to fix several security issues.

The following vulnerabilities were fixed:

* CVE-2015-1931: IBM Java Security Components store plain text data in memory dumps, which could allow a local attacker to obtain information to aid in further attacks against the system.
* CVE-2015-2590: Easily exploitable vulnerability in the Libraries component allowed successful unauthenticated network attacks via multiple protocols. Successful attack of this vulnerability could have resulted in unauthorized Operating System takeover including arbitrary code execution.
* CVE-2015-2601: Easily exploitable vulnerability in the JCE component allowed successful unauthenticated network attacks via multiple protocols. Successful attack of this vulnerability could have resulted in unauthorized read access to a subset of Java accessible data.
* CVE-2015-2613: Easily exploitable vulnerability in the JCE component allowed successful unauthenticated network attacks via multiple protocols. Successful attack of this vulnerability could have resulted in unauthorized read access to a subset of Java SE, Java SE Embedded accessible data.
* CVE-2015-2619: Easily exploitable vulnerability in the 2D component allowed successful unauthenticated network attacks via multiple protocols. Successful attack of this vulnerability could have resulted in unauthorized read access to a subset of Java accessible data.
* CVE-2015-2621: Easily exploitable vulnerability in the JMX component allowed successful unauthenticated network attacks via multiple protocols. Successful attack of this vulnerability could have resulted in unauthorized read access to a subset of Java accessible data.
* CVE-2015-2625: Very difficult to exploit vulnerability in the JSSE component allowed successful unauthenticated network attacks via SSL/TLS. Successful attack of this vulnerability could have resulted in unauthorized read access to a subset of Java accessible data.
* CVE-2015-2632: Easily exploitable vulnerability in the 2D component allowed successful unauthenticated network attacks via multiple protocols. Successful attack of this vulnerability could have resulted in unauthorized read access to a subset of Java accessible data.
* CVE-2015-2637: Easily exploitable vulnerability in the 2D component allowed successful unauthenticated network attacks via multiple protocols. Successful attack of this vulnerability could have resulted in unauthorized read access to a subset of Java accessible data.
* CVE-2015-2638: Easily exploitable vulnerability in the 2D component allowed successful unauthenticated network attacks via multiple protocols. Successful attack of this vulnerability could have resulted in unauthorized Operating System takeover including arbitrary code execution.
* CVE-2015-2664: Difficult to exploit vulnerability in the Deployment component requiring logon to Operating System. Successful attack of ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'java-1_7_1-ibm' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_1-ibm", rpm:"java-1_7_1-ibm~1.7.1_sr3.10~3.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_1-ibm-alsa", rpm:"java-1_7_1-ibm-alsa~1.7.1_sr3.10~3.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_1-ibm-jdbc", rpm:"java-1_7_1-ibm-jdbc~1.7.1_sr3.10~3.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_1-ibm-plugin", rpm:"java-1_7_1-ibm-plugin~1.7.1_sr3.10~3.1", rls:"SLES11.0SP4"))) {
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
