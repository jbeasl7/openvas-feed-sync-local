# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.1319.1");
  script_cve_id("CVE-2015-2590", "CVE-2015-2596", "CVE-2015-2597", "CVE-2015-2601", "CVE-2015-2613", "CVE-2015-2619", "CVE-2015-2621", "CVE-2015-2625", "CVE-2015-2627", "CVE-2015-2628", "CVE-2015-2632", "CVE-2015-2637", "CVE-2015-2638", "CVE-2015-2664", "CVE-2015-2808", "CVE-2015-4000", "CVE-2015-4729", "CVE-2015-4731", "CVE-2015-4732", "CVE-2015-4733", "CVE-2015-4736", "CVE-2015-4748", "CVE-2015-4749", "CVE-2015-4760");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:43:11 +0000 (Tue, 16 Jul 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:1319-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:1319-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20151319-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/938248");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-July/001515.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_7_0-openjdk' package(s) announced via the SUSE-SU-2015:1319-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"OpenJDK was updated to 2.6.1 - OpenJDK 7u85 to fix security issues and bugs.

The following vulnerabilities were fixed:

* CVE-2015-2590: Easily exploitable vulnerability in the Libraries component allowed successful unauthenticated network attacks via multiple protocols. Successful attack of this vulnerability could have resulted in unauthorized Operating System takeover including arbitrary code execution.
* CVE-2015-2596: Difficult to exploit vulnerability in the Hotspot component allowed successful unauthenticated network attacks via multiple protocols. Successful attack of this vulnerability could have resulted in unauthorized update, insert or delete access to some Java accessible data.
* CVE-2015-2597: Easily exploitable vulnerability in the Install component requiring logon to Operating System. Successful attack of this vulnerability could have resulted in unauthorized Operating System takeover including arbitrary code execution.
* CVE-2015-2601: Easily exploitable vulnerability in the JCE component allowed successful unauthenticated network attacks via multiple protocols. Successful attack of this vulnerability could have resulted in unauthorized read access to a subset of Java accessible data.
* CVE-2015-2613: Easily exploitable vulnerability in the JCE component allowed successful unauthenticated network attacks via multiple protocols. Successful attack of this vulnerability could have resulted in unauthorized read access to a subset of Java SE, Java SE Embedded accessible data.
* CVE-2015-2619: Easily exploitable vulnerability in the 2D component allowed successful unauthenticated network attacks via multiple protocols. Successful attack of this vulnerability could have resulted in unauthorized read access to a subset of Java accessible data.
* CVE-2015-2621: Easily exploitable vulnerability in the JMX component allowed successful unauthenticated network attacks via multiple protocols. Successful attack of this vulnerability could have resulted in unauthorized read access to a subset of Java accessible data.
* CVE-2015-2625: Very difficult to exploit vulnerability in the JSSE component allowed successful unauthenticated network attacks via SSL/TLS. Successful attack of this vulnerability could have resulted in unauthorized read access to a subset of Java accessible data.
* CVE-2015-2627: Very difficult to exploit vulnerability in the Install component allowed successful unauthenticated network attacks via multiple protocols. Successful attack of this vulnerability could have resulted in unauthorized read access to a subset of Java accessible data.
* CVE-2015-2628: Easily exploitable vulnerability in the CORBA component allowed successful unauthenticated network attacks via multiple protocols. Successful attack of this vulnerability could have resulted in unauthorized Operating System takeover including arbitrary code execution.
* CVE-2015-2632: Easily ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'java-1_7_0-openjdk' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk", rpm:"java-1_7_0-openjdk~1.7.0.85~18.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-demo", rpm:"java-1_7_0-openjdk-demo~1.7.0.85~18.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-devel", rpm:"java-1_7_0-openjdk-devel~1.7.0.85~18.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-headless", rpm:"java-1_7_0-openjdk-headless~1.7.0.85~18.2", rls:"SLES12.0"))) {
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
