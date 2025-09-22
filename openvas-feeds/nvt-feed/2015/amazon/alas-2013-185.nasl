# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120271");
  script_cve_id("CVE-2013-0401", "CVE-2013-1488", "CVE-2013-1518", "CVE-2013-1537", "CVE-2013-1557", "CVE-2013-1558", "CVE-2013-1569", "CVE-2013-2383", "CVE-2013-2384", "CVE-2013-2415", "CVE-2013-2417", "CVE-2013-2419", "CVE-2013-2420", "CVE-2013-2421", "CVE-2013-2422", "CVE-2013-2424", "CVE-2013-2426", "CVE-2013-2429", "CVE-2013-2430", "CVE-2013-2431");
  script_tag(name:"creation_date", value:"2015-09-08 11:22:02 +0000 (Tue, 08 Sep 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Amazon Linux: Security Advisory (ALAS-2013-185)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2013-185");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2013-185.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1.6.0-openjdk' package(s) announced via the ALAS-2013-185 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws were discovered in the font layout engine in the 2D component. An untrusted Java application or applet could possibly use these flaws to trigger Java Virtual Machine memory corruption. (CVE-2013-1569, CVE-2013-2383, CVE-2013-2384)

Multiple improper permission check issues were discovered in the Beans, Libraries, JAXP, and RMI components in OpenJDK. An untrusted Java application or applet could use these flaws to bypass Java sandbox restrictions. (CVE-2013-1558, CVE-2013-2422, CVE-2013-1518, CVE-2013-1557)

The previous default value of the java.rmi.server.useCodebaseOnly property permitted the RMI implementation to automatically load classes from remotely specified locations. An attacker able to connect to an application using RMI could use this flaw to make the application execute arbitrary code. (CVE-2013-1537)

The 2D component did not properly process certain images. An untrusted Java application or applet could possibly use this flaw to trigger Java Virtual Machine memory corruption. (CVE-2013-2420)

It was discovered that the Hotspot component did not properly handle certain intrinsic frames, and did not correctly perform MethodHandle lookups. An untrusted Java application or applet could use these flaws to bypass Java sandbox restrictions. (CVE-2013-2431, CVE-2013-2421)

It was discovered that JPEGImageReader and JPEGImageWriter in the ImageIO component did not protect against modification of their state while performing certain native code operations. An untrusted Java application or applet could possibly use these flaws to trigger Java Virtual Machine memory corruption. (CVE-2013-2429, CVE-2013-2430)

The JDBC driver manager could incorrectly call the toString() method in JDBC drivers, and the ConcurrentHashMap class could incorrectly call the defaultReadObject() method. An untrusted Java application or applet could possibly use these flaws to bypass Java sandbox restrictions. (CVE-2013-1488, CVE-2013-2426)

The sun.awt.datatransfer.ClassLoaderObjectInputStream class may incorrectly invoke the system class loader. An untrusted Java application or applet could possibly use this flaw to bypass certain Java sandbox restrictions. (CVE-2013-0401)

Flaws were discovered in the Network component's InetAddress serialization, and the 2D component's font handling. An untrusted Java application or applet could possibly use these flaws to crash the Java Virtual Machine. (CVE-2013-2417, CVE-2013-2419)

The MBeanInstantiator class implementation in the OpenJDK JMX component did not properly check class access before creating new instances. An untrusted Java application or applet could use this flaw to create instances of non-public classes. (CVE-2013-2424)

It was discovered that JAX-WS could possibly create temporary files with insecure permissions. A local attacker could use this flaw to access temporary files created by an application using JAX-WS. (CVE-2013-2415)");

  script_tag(name:"affected", value:"'java-1.6.0-openjdk' package(s) on Amazon Linux.");

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

if(release == "AMAZON") {

  if(!isnull(res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~1.6.0.0~61.1.11.11.53.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.6.0-openjdk-debuginfo", rpm:"java-1.6.0-openjdk-debuginfo~1.6.0.0~61.1.11.11.53.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.6.0-openjdk-demo", rpm:"java-1.6.0-openjdk-demo~1.6.0.0~61.1.11.11.53.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.6.0-openjdk-devel", rpm:"java-1.6.0-openjdk-devel~1.6.0.0~61.1.11.11.53.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.6.0-openjdk-javadoc", rpm:"java-1.6.0-openjdk-javadoc~1.6.0.0~61.1.11.11.53.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.6.0-openjdk-src", rpm:"java-1.6.0-openjdk-src~1.6.0.0~61.1.11.11.53.amzn1", rls:"AMAZON"))) {
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
