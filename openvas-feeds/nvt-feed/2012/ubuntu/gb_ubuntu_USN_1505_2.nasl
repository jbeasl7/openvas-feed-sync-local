# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841127");
  script_cve_id("CVE-2012-1711", "CVE-2012-1713", "CVE-2012-1716", "CVE-2012-1717", "CVE-2012-1718", "CVE-2012-1719", "CVE-2012-1723", "CVE-2012-1724", "CVE-2012-1725");
  script_tag(name:"creation_date", value:"2012-09-06 05:22:05 +0000 (Thu, 06 Sep 2012)");
  script_version("2025-08-15T05:40:49+0000");
  script_tag(name:"last_modification", value:"2025-08-15 05:40:49 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:38:00 +0000 (Tue, 16 Jul 2024)");

  script_name("Ubuntu: Security Advisory (USN-1505-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(11\.04|11\.10)");

  script_xref(name:"Advisory-ID", value:"USN-1505-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1505-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1025553");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'icedtea-web' package(s) announced via the USN-1505-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-1505-1 fixed vulnerabilities in OpenJDK 6. As part of the update,
IcedTea-Web packages were upgraded to a new version. That upgrade
introduced a regression which prevented the IcedTea-Web plugin from
working with the Chromium web browser in Ubuntu 11.04 and Ubuntu 11.10.
This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that multiple flaws existed in the CORBA (Common
 Object Request Broker Architecture) implementation in OpenJDK. An
 attacker could create a Java application or applet that used these
 flaws to bypass Java sandbox restrictions or modify immutable object
 data. (CVE-2012-1711, CVE-2012-1719)

 It was discovered that multiple flaws existed in the OpenJDK font
 manager's layout lookup implementation. A attacker could specially
 craft a font file that could cause a denial of service through
 crashing the JVM (Java Virtual Machine) or possibly execute arbitrary
 code. (CVE-2012-1713)

 It was discovered that the SynthLookAndFeel class from Swing in
 OpenJDK did not properly prevent access to certain UI elements
 from outside the current application context. An attacker could
 create a Java application or applet that used this flaw to cause a
 denial of service through crashing the JVM or bypass Java sandbox
 restrictions. (CVE-2012-1716)

 It was discovered that OpenJDK runtime library classes could create
 temporary files with insecure permissions. A local attacker could
 use this to gain access to sensitive information. (CVE-2012-1717)

 It was discovered that OpenJDK did not handle CRLs (Certificate
 Revocation Lists) properly. A remote attacker could use this to gain
 access to sensitive information. (CVE-2012-1718)

 It was discovered that the OpenJDK HotSpot Virtual Machine did not
 properly verify the bytecode of the class to be executed. A remote
 attacker could create a Java application or applet that used this
 to cause a denial of service through crashing the JVM or bypass Java
 sandbox restrictions. (CVE-2012-1723, CVE-2012-1725)

 It was discovered that the OpenJDK XML (Extensible Markup Language)
 parser did not properly handle some XML documents. An attacker could
 create an XML document that caused a denial of service in a Java
 application or applet parsing the document. (CVE-2012-1724)

 As part of this update, the IcedTea web browser applet plugin was
 updated for Ubuntu 10.04 LTS, Ubuntu 11.04, and Ubuntu 11.10.");

  script_tag(name:"affected", value:"'icedtea-web' package(s) on Ubuntu 11.04, Ubuntu 11.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU11.04") {

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-6-plugin", ver:"1.2-2ubuntu0.11.04.3", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU11.10") {

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-6-plugin", ver:"1.2-2ubuntu0.11.10.3", rls:"UBUNTU11.10"))) {
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
