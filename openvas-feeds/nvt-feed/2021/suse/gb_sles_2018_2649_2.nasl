# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2649.2");
  script_cve_id("CVE-2018-12539", "CVE-2018-1517", "CVE-2018-1656", "CVE-2018-2940", "CVE-2018-2952", "CVE-2018-2973");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-23 15:25:55 +0000 (Tue, 23 Oct 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2649-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2649-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182649-2.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104668");
  script_xref(name:"URL", value:"https://developer.ibm.com/javasdk/support/security-vulnerabilities/#IBM_Security_Update_August_2018");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-October/004712.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_7_1-ibm' package(s) announced via the SUSE-SU-2018:2649-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-1_7_1-ibm fixes the following issues:

Security issues fixed:

- CVE-2018-1517: Fixed a flaw in the java.math component in IBM SDK, which may
 allow an attacker to inflict a denial-of-service attack with specially
 crafted String data.
- CVE-2018-1656: Protect against path traversal attacks when extracting
 compressed dump files.
- CVE-2018-2940: Fixed an easily exploitable vulnerability in the libraries
 subcomponent, which allowed unauthenticated attackers with network access
 via multiple protocols to compromise the Java SE, leading to
 unauthorized read access.
- CVE-2018-2952: Fixed an easily exploitable vulnerability in the concurrency
 subcomponent, which allowed unauthenticated attackers with network access
 via multiple protocols to compromise the Java SE, leading to denial of
 service.
- CVE-2018-2973: Fixed a difficult to exploit vulnerability in the JSSE
 subcomponent, which allowed unauthenticated attackers with network access
 via SSL/TLS to compromise the Java SE, leading to unauthorized creation,
 deletion or modification access to critical data.
- CVE-2018-12539: Fixed a vulnerability in which users other than the process
 owner may be able to use Java Attach API to connect to the IBM JVM on the
 same machine and use Attach API operations, including the ability to execute
 untrusted arbitrary code.

Other changes made:

- Various JIT/JVM crash fixes
- Version update to 7.1.4.30 (bsc#1104668)

You can find detailed information about this update [here]([link moved to references]).");

  script_tag(name:"affected", value:"'java-1_7_1-ibm' package(s) on SUSE Linux Enterprise Server 12-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_1-ibm", rpm:"java-1_7_1-ibm~1.7.1_sr4.30~38.26.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_1-ibm-alsa", rpm:"java-1_7_1-ibm-alsa~1.7.1_sr4.30~38.26.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_1-ibm-devel", rpm:"java-1_7_1-ibm-devel~1.7.1_sr4.30~38.26.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_1-ibm-jdbc", rpm:"java-1_7_1-ibm-jdbc~1.7.1_sr4.30~38.26.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_1-ibm-plugin", rpm:"java-1_7_1-ibm-plugin~1.7.1_sr4.30~38.26.1", rls:"SLES12.0SP2"))) {
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
