# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841505");
  script_cve_id("CVE-2013-1500", "CVE-2013-1571", "CVE-2013-2407", "CVE-2013-2412", "CVE-2013-2443", "CVE-2013-2444", "CVE-2013-2445", "CVE-2013-2446", "CVE-2013-2447", "CVE-2013-2448", "CVE-2013-2449", "CVE-2013-2450", "CVE-2013-2451", "CVE-2013-2452", "CVE-2013-2453", "CVE-2013-2454", "CVE-2013-2455", "CVE-2013-2456", "CVE-2013-2457", "CVE-2013-2458", "CVE-2013-2459", "CVE-2013-2460", "CVE-2013-2461", "CVE-2013-2463", "CVE-2013-2465", "CVE-2013-2469", "CVE-2013-2470", "CVE-2013-2471", "CVE-2013-2472", "CVE-2013-2473");
  script_tag(name:"creation_date", value:"2013-08-01 13:38:53 +0000 (Thu, 01 Aug 2013)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1907-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|12\.10|13\.04)");

  script_xref(name:"Advisory-ID", value:"USN-1907-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1907-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1201908");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'icedtea-web' package(s) announced via the USN-1907-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-1907-1 fixed vulnerabilities in OpenJDK 7. Due to upstream changes,
IcedTea Web needed an update to work with the new OpenJDK 7.

Original advisory details:

 Several vulnerabilities were discovered in the OpenJDK JRE related to
 information disclosure and data integrity. An attacker could exploit these
 to expose sensitive data over the network. (CVE-2013-1500, CVE-2013-2454,
 CVE-2013-2458)

 A vulnerability was discovered in the OpenJDK Javadoc related to data
 integrity. (CVE-2013-1571)

 A vulnerability was discovered in the OpenJDK JRE related to information
 disclosure and availability. An attacker could exploit this to cause a
 denial of service or expose sensitive data over the network.
 (CVE-2013-2407)

 Several vulnerabilities were discovered in the OpenJDK JRE related to
 information disclosure. An attacker could exploit these to expose sensitive
 data over the network. (CVE-2013-2412, CVE-2013-2443, CVE-2013-2446,
 CVE-2013-2447, CVE-2013-2449, CVE-2013-2452, CVE-2013-2456)

 Several vulnerabilities were discovered in the OpenJDK JRE related to
 availability. An attacker could exploit these to cause a denial of service.
 (CVE-2013-2444, CVE-2013-2445, CVE-2013-2450)

 Several vulnerabilities were discovered in the OpenJDK JRE related to
 information disclosure, data integrity and availability. An attacker could
 exploit these to cause a denial of service or expose sensitive data over
 the network. (CVE-2013-2448, CVE-2013-2451, CVE-2013-2459, CVE-2013-2460,
 CVE-2013-2461, CVE-2013-2463, CVE-2013-2465, CVE-2013-2469, CVE-2013-2470,
 CVE-2013-2471, CVE-2013-2472, CVE-2013-2473)

 Several vulnerabilities were discovered in the OpenJDK JRE related to data
 integrity. (CVE-2013-2453, CVE-2013-2455, CVE-2013-2457)");

  script_tag(name:"affected", value:"'icedtea-web' package(s) on Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.04.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-netx", ver:"1.2.3-0ubuntu0.12.04.3", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU12.10") {

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-netx", ver:"1.3.2-1ubuntu0.12.10.2", rls:"UBUNTU12.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU13.04") {

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-netx", ver:"1.3.2-1ubuntu1.1", rls:"UBUNTU13.04"))) {
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
