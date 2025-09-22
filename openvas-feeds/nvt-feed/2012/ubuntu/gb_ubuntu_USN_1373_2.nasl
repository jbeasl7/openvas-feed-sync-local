# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840919");
  script_cve_id("CVE-2011-3563", "CVE-2011-5035", "CVE-2012-0497", "CVE-2012-0501", "CVE-2012-0502", "CVE-2012-0503", "CVE-2012-0505", "CVE-2012-0506", "CVE-2012-0507");
  script_tag(name:"creation_date", value:"2012-03-07 05:49:39 +0000 (Wed, 07 Mar 2012)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1373-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|10\.10|11\.04)");

  script_xref(name:"Advisory-ID", value:"USN-1373-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1373-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-6b18' package(s) announced via the USN-1373-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN 1373-1 fixed vulnerabilities in OpenJDK 6 in Ubuntu 10.04 LTS,
Ubuntu 10.10 and Ubuntu 11.04 for all architectures except for ARM
(armel). This provides the corresponding OpenJDK 6 update for use
with the ARM (armel) architecture in Ubuntu 10.04 LTS, Ubuntu 10.10
and Ubuntu 11.04.

Original advisory details:

 It was discovered that the Java HttpServer class did not limit the
 number of headers read from a HTTP request. A remote attacker could
 cause a denial of service by sending special requests that trigger
 hash collisions predictably. (CVE-2011-5035)

 ATTENTION: this update changes previous Java HttpServer class behavior
 by limiting the number of request headers to 200. This may be increased
 by adjusting the sun.net.httpserver.maxReqHeaders property.

 It was discovered that the Java Sound component did not properly
 check buffer boundaries. A remote attacker could use this to cause
 a denial of service or view confidential data. (CVE-2011-3563)

 It was discovered that the Java2D implementation does not properly
 check graphics rendering objects before passing them to the native
 renderer. A remote attacker could use this to cause a denial of
 service or to bypass Java sandbox restrictions. (CVE-2012-0497)

 It was discovered that an off-by-one error exists in the Java ZIP
 file processing code. An attacker could us this to cause a denial of
 service through a maliciously crafted ZIP file. (CVE-2012-0501)

 It was discovered that the Java AWT KeyboardFocusManager did not
 properly enforce keyboard focus security policy. A remote attacker
 could use this with an untrusted application or applet to grab keyboard
 focus and possibly expose confidential data. (CVE-2012-0502)

 It was discovered that the Java TimeZone class did not properly enforce
 security policy around setting the default time zone. A remote attacker
 could use this with an untrusted application or applet to set a new
 default time zone and bypass Java sandbox restrictions. (CVE-2012-0503)

 It was discovered the Java ObjectStreamClass did not throw
 an accurately identifiable exception when a deserialization
 failure occurred. A remote attacker could use this with
 an untrusted application or applet to bypass Java sandbox
 restrictions. (CVE-2012-0505)

 It was discovered that the Java CORBA implementation did not properly
 protect repository identifiers on certain CORBA objects. A remote
 attacker could use this to corrupt object data. (CVE-2012-0506)

 It was discovered that the Java AtomicReferenceArray class
 implementation did not properly check if an array was of
 the expected Object[] type. A remote attacker could use this
 with a malicious application or applet to bypass Java sandbox
 restrictions. (CVE-2012-0507)");

  script_tag(name:"affected", value:"'openjdk-6b18' package(s) on Ubuntu 10.04, Ubuntu 10.10, Ubuntu 11.04.");

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

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-6-jre-cacao", ver:"6b18-1.8.13-0ubuntu1~10.04.1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b18-1.8.13-0ubuntu1~10.04.1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b18-1.8.13-0ubuntu1~10.04.1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-zero", ver:"6b18-1.8.13-0ubuntu1~10.04.1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU10.10") {

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-6-jre-cacao", ver:"6b18-1.8.13-0ubuntu1~10.10.1", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b18-1.8.13-0ubuntu1~10.10.1", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b18-1.8.13-0ubuntu1~10.10.1", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-zero", ver:"6b18-1.8.13-0ubuntu1~10.10.1", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU11.04") {

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-6-jre-cacao", ver:"6b18-1.8.13-0ubuntu1~11.04.1", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-6-jre-jamvm", ver:"6b18-1.8.13-0ubuntu1~11.04.1", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b18-1.8.13-0ubuntu1~11.04.1", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b18-1.8.13-0ubuntu1~11.04.1", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-zero", ver:"6b18-1.8.13-0ubuntu1~11.04.1", rls:"UBUNTU11.04"))) {
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
