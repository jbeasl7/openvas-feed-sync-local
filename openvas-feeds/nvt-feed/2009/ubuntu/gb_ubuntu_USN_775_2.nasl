# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64199");
  script_tag(name:"creation_date", value:"2009-06-15 17:20:43 +0000 (Mon, 15 Jun 2009)");
  script_version("2023-06-21T05:06:20+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:20 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-775-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(6\.06\ LTS|8\.04\ LTS|8\.10)");

  script_xref(name:"Advisory-ID", value:"USN-775-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-775-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/384193");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'quagga' package(s) announced via the USN-775-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-775-1 fixed vulnerabilities in Quagga. The preventative fixes
introduced in Quagga prior to Ubuntu 9.04 could result in BGP service
failures. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that the BGP service in Quagga did not correctly
 handle certain AS paths containing 4-byte ASNs. An authenticated remote
 attacker could exploit this flaw to cause bgpd to abort, leading to a
 denial of service.");

  script_tag(name:"affected", value:"'quagga' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 8.10.");

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

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"quagga", ver:"0.99.2-1ubuntu3.6", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU8.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"quagga", ver:"0.99.9-2ubuntu1.3", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU8.10") {

  if(!isnull(res = isdpkgvuln(pkg:"quagga", ver:"0.99.9-6ubuntu0.2", rls:"UBUNTU8.10"))) {
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
