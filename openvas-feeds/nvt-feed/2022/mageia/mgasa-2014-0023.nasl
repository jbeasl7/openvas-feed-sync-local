# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0023");
  script_cve_id("CVE-2013-5878", "CVE-2013-5884", "CVE-2013-5893", "CVE-2013-5896", "CVE-2013-5907", "CVE-2013-5910", "CVE-2014-0368", "CVE-2014-0373", "CVE-2014-0376", "CVE-2014-0411", "CVE-2014-0416", "CVE-2014-0422", "CVE-2014-0423", "CVE-2014-0428");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Mageia: Security Advisory (MGASA-2014-0023)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0023");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0023.html");
  script_xref(name:"URL", value:"http://mail.openjdk.java.net/pipermail/distro-pkg-dev/2014-January/025800.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujan2014-1972949.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=12317");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2014-0026.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1.7.0-openjdk' package(s) announced via the MGASA-2014-0023 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated java-1.7.0-openjdk packages fix security vulnerabilities:

An input validation flaw was discovered in the font layout engine in the 2D
component. A specially crafted font file could trigger Java Virtual Machine
memory corruption when processed. An untrusted Java application or applet
could possibly use this flaw to bypass Java sandbox restrictions
(CVE-2013-5907).

Multiple improper permission check issues were discovered in the CORBA,
JNDI, and Libraries components in OpenJDK. An untrusted Java application or
applet could use these flaws to bypass Java sandbox restrictions
(CVE-2014-0428, CVE-2014-0422, CVE-2013-5893).

Multiple improper permission check issues were discovered in the
Serviceability, Security, CORBA, JAAS, JAXP, and Networking components in
OpenJDK. An untrusted Java application or applet could use these flaws to
bypass certain Java sandbox restrictions (CVE-2014-0373, CVE-2013-5878,
CVE-2013-5910, CVE-2013-5896, CVE-2013-5884, CVE-2014-0416, CVE-2014-0376,
CVE-2014-0368).

It was discovered that the Beans component did not restrict processing of
XML external entities. This flaw could cause a Java application using Beans
to leak sensitive information, or affect application availability
(CVE-2014-0423).

It was discovered that the JSSE component could leak timing information
during the TLS/SSL handshake. This could possibly lead to disclosure of
information about the used encryption keys (CVE-2014-0411).");

  script_tag(name:"affected", value:"'java-1.7.0-openjdk' package(s) on Mageia 3.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk", rpm:"java-1.7.0-openjdk~1.7.0.60~2.4.4.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk-accessibility", rpm:"java-1.7.0-openjdk-accessibility~1.7.0.60~2.4.4.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk-demo", rpm:"java-1.7.0-openjdk-demo~1.7.0.60~2.4.4.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk-devel", rpm:"java-1.7.0-openjdk-devel~1.7.0.60~2.4.4.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk-headless", rpm:"java-1.7.0-openjdk-headless~1.7.0.60~2.4.4.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk-javadoc", rpm:"java-1.7.0-openjdk-javadoc~1.7.0.60~2.4.4.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk-src", rpm:"java-1.7.0-openjdk-src~1.7.0.60~2.4.4.1.mga3", rls:"MAGEIA3"))) {
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
