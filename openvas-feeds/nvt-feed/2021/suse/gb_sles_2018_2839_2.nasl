# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2839.2");
  script_cve_id("CVE-2016-0705", "CVE-2017-3732", "CVE-2017-3736", "CVE-2018-12539", "CVE-2018-1517", "CVE-2018-1656", "CVE-2018-2940", "CVE-2018-2952", "CVE-2018-2964", "CVE-2018-2973");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-03-07 15:45:47 +0000 (Mon, 07 Mar 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2839-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2839-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182839-2.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104668");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-October/004738.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_8_0-ibm' package(s) announced via the SUSE-SU-2018:2839-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-1_8_0-ibm to 8.0.5.20 fixes the following security issues:

- CVE-2018-2952: Vulnerability in subcomponent: Concurrency. Difficult to
 exploit vulnerability allowed unauthenticated attacker with network access via
 multiple protocols to compromise Java SE, Java SE Embedded, JRockit. Successful
 attacks of this vulnerability can result in unauthorized ability to cause a
 partial denial of service (partial DOS) of Java SE, Java SE Embedded, JRockit
 (bsc#1104668)
- CVE-2018-2940: Vulnerability in subcomponent: Libraries. Easily exploitable
 vulnerability allowed unauthenticated attacker with network access via multiple
 protocols to compromise Java SE, Java SE Embedded. Successful attacks require
 human interaction from a person other than the attacker. Successful attacks of
 this vulnerability can result in unauthorized read access to a subset of Java
 SE, Java SE Embedded accessible data (bsc#1104668)
- CVE-2018-2973: Vulnerability in subcomponent: JSSE. Difficult to exploit
 vulnerability allowed unauthenticated attacker with network access via SSL/TLS
 to compromise Java SE, Java SE Embedded. Successful attacks of this
 vulnerability can result in unauthorized creation, deletion or modification
 access to critical data or all Java SE, Java SE Embedded accessible data
 (bsc#1104668)
- CVE-2018-2964: Vulnerability in subcomponent: Deployment. Difficult to
 exploit vulnerability allowed unauthenticated attacker with network access via
 multiple protocols to compromise Java SE. Successful attacks require human
 interaction from a person other than the attacker. Successful attacks of this
 vulnerability can result in takeover of Java SE. (bsc#1104668)
- CVE-2016-0705: Prevent double free in the dsa_priv_decode function that
 allowed remote attackers to cause a denial of service (memory corruption) or
 possibly have unspecified other impact via a malformed DSA private key
 (bsc#1104668)
- CVE-2017-3732: Prevent carry propagating bug in the x86_64 Montgomery
 squaring procedure (bsc#1104668)
- CVE-2017-3736: Prevent carry propagating bug in the x86_64 Montgomery
 squaring procedure (bsc#1104668)
- CVE-2018-1517: Unspecified vulnerability (bsc#1104668)
- CVE-2018-1656: Unspecified vulnerability (bsc#1104668)
- CVE-2018-12539: Users other than the process owner might have been able to
 use Java Attach API to connect to an IBM JVM on the same machine and use Attach
 API operations, which includes the ability to execute untrusted native code
 (bsc#1104668)");

  script_tag(name:"affected", value:"'java-1_8_0-ibm' package(s) on SUSE Linux Enterprise Server 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm", rpm:"java-1_8_0-ibm~1.8.0_sr5.20~30.36.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-alsa", rpm:"java-1_8_0-ibm-alsa~1.8.0_sr5.20~30.36.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-devel", rpm:"java-1_8_0-ibm-devel~1.8.0_sr5.20~30.36.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-plugin", rpm:"java-1_8_0-ibm-plugin~1.8.0_sr5.20~30.36.1", rls:"SLES12.0SP2"))) {
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
