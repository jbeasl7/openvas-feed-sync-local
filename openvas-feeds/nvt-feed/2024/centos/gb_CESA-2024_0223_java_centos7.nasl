# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884321");
  script_version("2024-04-11T05:05:26+0000");
  script_cve_id("CVE-2024-20918", "CVE-2024-20952", "CVE-2024-20919", "CVE-2024-20921", "CVE-2024-20926", "CVE-2024-20945");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_tag(name:"last_modification", value:"2024-04-11 05:05:26 +0000 (Thu, 11 Apr 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-16 22:15:42 +0000 (Tue, 16 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-03-05 14:32:59 +0000 (Tue, 05 Mar 2024)");
  script_name("CentOS: Security Advisory for java (CESA-2024:0223)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2024:0223");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2024-January/099218.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java'
  package(s) announced via the CESA-2024:0223 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The java-1.8.0-openjdk packages provide the OpenJDK 8 Java Runtime Environment and the OpenJDK 8 Java Software Development Kit.

Security Fix(es):

  * OpenJDK: array out-of-bounds access due to missing range check in C1 compiler (8314468) (CVE-2024-20918)

  * OpenJDK: RSA padding issue and timing side-channel attack against TLS (8317547) (CVE-2024-20952)

  * OpenJDK: JVM class file verifier flaw allows unverified bytecode execution (8314295) (CVE-2024-20919)

  * OpenJDK: range check loop optimization issue (8314307) (CVE-2024-20921)

  * OpenJDK: arbitrary Java code execution in Nashorn (8314284) (CVE-2024-20926)

  * OpenJDK: logging of digital signature private keys (8316976) (CVE-2024-20945)

For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and other related information, refer to the CVE page(s) listed in the References section.
Bug Fix(es):

  * In the previous release in October 2023 (8u392), the RPMs were changed to use Provides for java, jre, java-headless, jre-headless, java-devel and java-sdk which included the full RPM version. This prevented the Provides being used to resolve a dependency on Java 1.8.0 (for example, &quot, Requires: java-headless 1:1.8.0&quot, ). This change has now been reverted to the old &quot, 1:1.8.0&quot, value. (RHEL-19630)");

  script_tag(name:"affected", value:"'java' package(s) on CentOS 7.");

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

if(release == "CentOS7") {

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk", rpm:"java-1.8.0-openjdk~1.8.0.402.b06~1.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-accessibility", rpm:"java-1.8.0-openjdk-accessibility~1.8.0.402.b06~1.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-demo", rpm:"java-1.8.0-openjdk-demo~1.8.0.402.b06~1.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-devel", rpm:"java-1.8.0-openjdk-devel~1.8.0.402.b06~1.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-headless", rpm:"java-1.8.0-openjdk-headless~1.8.0.402.b06~1.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-javadoc", rpm:"java-1.8.0-openjdk-javadoc~1.8.0.402.b06~1.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-javadoc-zip", rpm:"java-1.8.0-openjdk-javadoc-zip~1.8.0.402.b06~1.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-src", rpm:"java-1.8.0-openjdk-src~1.8.0.402.b06~1.el7_9", rls:"CentOS7"))) {
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
