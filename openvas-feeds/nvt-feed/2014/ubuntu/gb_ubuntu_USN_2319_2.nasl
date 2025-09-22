# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841944");
  script_cve_id("CVE-2014-2483", "CVE-2014-2490", "CVE-2014-4209", "CVE-2014-4216", "CVE-2014-4218", "CVE-2014-4219", "CVE-2014-4221", "CVE-2014-4223", "CVE-2014-4244", "CVE-2014-4252", "CVE-2014-4262", "CVE-2014-4263", "CVE-2014-4264", "CVE-2014-4266", "CVE-2014-4268");
  script_tag(name:"creation_date", value:"2014-08-26 03:53:09 +0000 (Tue, 26 Aug 2014)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2319-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-2319-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2319-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1360392");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-7' package(s) announced via the USN-2319-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-2319-1 fixed vulnerabilities in OpenJDK 7. Due to an upstream
regression, verifying of the init method call would fail when it was done
from inside a branch when stack frames are activated. This update fixes the
problem.

We apologize for the inconvenience.

Original advisory details:

 Several vulnerabilities were discovered in the OpenJDK JRE related to
 information disclosure, data integrity and availability. An attacker could
 exploit these to cause a denial of service or expose sensitive data over
 the network. (CVE-2014-2483, CVE-2014-2490, CVE-2014-4216, CVE-2014-4219,
 CVE-2014-4223, CVE-2014-4262)

 Several vulnerabilities were discovered in the OpenJDK JRE related to
 information disclosure and data integrity. An attacker could exploit these
 to expose sensitive data over the network. (CVE-2014-4209, CVE-2014-4244,
 CVE-2014-4263)

 Two vulnerabilities were discovered in the OpenJDK JRE related to data
 integrity. (CVE-2014-4218, CVE-2014-4266)

 A vulnerability was discovered in the OpenJDK JRE related to availability.
 An attacker could exploit this to cause a denial of service.
 (CVE-2014-4264)

 Several vulnerabilities were discovered in the OpenJDK JRE related to
 information disclosure. An attacker could exploit these to expose sensitive
 data over the network. (CVE-2014-4221, CVE-2014-4252, CVE-2014-4268)");

  script_tag(name:"affected", value:"'openjdk-7' package(s) on Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-7-jre-jamvm", ver:"7u65-2.5.1-4ubuntu1~0.14.04.2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre", ver:"7u65-2.5.1-4ubuntu1~0.14.04.2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre-headless", ver:"7u65-2.5.1-4ubuntu1~0.14.04.2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre-lib", ver:"7u65-2.5.1-4ubuntu1~0.14.04.2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre-zero", ver:"7u65-2.5.1-4ubuntu1~0.14.04.2", rls:"UBUNTU14.04 LTS"))) {
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
