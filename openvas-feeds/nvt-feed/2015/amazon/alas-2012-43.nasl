# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120258");
  script_cve_id("CVE-2011-3563", "CVE-2011-3571", "CVE-2011-5035", "CVE-2012-0497", "CVE-2012-0501", "CVE-2012-0502", "CVE-2012-0503", "CVE-2012-0505", "CVE-2012-0506");
  script_tag(name:"creation_date", value:"2015-09-08 11:21:44 +0000 (Tue, 08 Sep 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Amazon Linux: Security Advisory (ALAS-2012-43)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2012-43");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2012-43.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1.6.0-openjdk' package(s) announced via the ALAS-2012-43 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Java2D did not properly check graphics rendering objects before passing them to the native renderer. Malicious input, or an untrusted Java application or applet could use this flaw to crash the Java Virtual Machine (JVM), or bypass Java sandbox restrictions. (CVE-2012-0497)

It was discovered that the exception thrown on deserialization failure did not always contain a proper identification of the cause of the failure. An untrusted Java application or applet could use this flaw to bypass Java sandbox restrictions. (CVE-2012-0505)

The AtomicReferenceArray class implementation did not properly check if the array was of the expected Object[] type. A malicious Java application or applet could use this flaw to bypass Java sandbox restrictions. (CVE-2011-3571)

It was discovered that the use of TimeZone.setDefault() was not restricted by the SecurityManager, allowing an untrusted Java application or applet to set a new default time zone, and hence bypass Java sandbox restrictions. (CVE-2012-0503)

The HttpServer class did not limit the number of headers read from HTTP requests. A remote attacker could use this flaw to make an application using HttpServer use an excessive amount of CPU time via a specially-crafted request. This update introduces a header count limit controlled using the sun.net.httpserver.maxReqHeaders property. The default value is 200. (CVE-2011-5035)

The Java Sound component did not properly check buffer boundaries. Malicious input, or an untrusted Java application or applet could use this flaw to cause the Java Virtual Machine (JVM) to crash or disclose a portion of its memory. (CVE-2011-3563)

A flaw was found in the AWT KeyboardFocusManager that could allow an untrusted Java application or applet to acquire keyboard focus and possibly steal sensitive information. (CVE-2012-0502)

It was discovered that the CORBA (Common Object Request Broker Architecture) implementation in Java did not properly protect repository identifiers on certain CORBA objects. This could have been used to modify immutable object data. (CVE-2012-0506)

An off-by-one flaw, causing a stack overflow, was found in the unpacker for ZIP files. A specially-crafted ZIP archive could cause the Java Virtual Machine (JVM) to crash when opened. (CVE-2012-0501)");

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

  if(!isnull(res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~1.6.0.0~52.1.10.6.41.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.6.0-openjdk-debuginfo", rpm:"java-1.6.0-openjdk-debuginfo~1.6.0.0~52.1.10.6.41.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.6.0-openjdk-demo", rpm:"java-1.6.0-openjdk-demo~1.6.0.0~52.1.10.6.41.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.6.0-openjdk-devel", rpm:"java-1.6.0-openjdk-devel~1.6.0.0~52.1.10.6.41.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.6.0-openjdk-javadoc", rpm:"java-1.6.0-openjdk-javadoc~1.6.0.0~52.1.10.6.41.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.6.0-openjdk-src", rpm:"java-1.6.0-openjdk-src~1.6.0.0~52.1.10.6.41.amzn1", rls:"AMAZON"))) {
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
