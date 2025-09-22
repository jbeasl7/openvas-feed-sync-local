# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841407");
  script_cve_id("CVE-2013-1926", "CVE-2013-1927");
  script_tag(name:"creation_date", value:"2013-04-25 05:19:59 +0000 (Thu, 25 Apr 2013)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-1804-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(11\.10|12\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-1804-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1804-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1171506");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'icedtea-web' package(s) announced via the USN-1804-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-1804-1 fixed vulnerabilities in IcedTea-Web. This update introduced
a regression with the Java Network Launching Protocol (JNLP) when fetching
content over SSL under certain configurations, such as when using the
community-supported IcedTead 7 browser plugin. This update fixes the
problem.

We apologize for the inconvenience.

Original advisory details:

 Jiri Vanek discovered that IcedTea-Web would use the same classloader for
 applets from different domains. A remote attacker could exploit this to
 expose sensitive information or potentially manipulate applets from other
 domains. (CVE-2013-1926)

 It was discovered that IcedTea-Web did not properly verify JAR files and
 was susceptible to the GIFAR attack. If a user were tricked into opening a
 malicious website, a remote attacker could potentially exploit this to
 execute code under certain circumstances. (CVE-2013-1927)");

  script_tag(name:"affected", value:"'icedtea-web' package(s) on Ubuntu 11.10, Ubuntu 12.04.");

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

if(release == "UBUNTU11.10") {

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-netx", ver:"1.2.3-0ubuntu0.11.10.2", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-7-plugin", ver:"1.2.3-0ubuntu0.12.04.2", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-netx", ver:"1.2.3-0ubuntu0.12.04.2", rls:"UBUNTU12.04 LTS"))) {
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
