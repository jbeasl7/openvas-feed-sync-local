# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841083");
  script_cve_id("CVE-2012-1948", "CVE-2012-1949", "CVE-2012-1951", "CVE-2012-1952", "CVE-2012-1953", "CVE-2012-1954", "CVE-2012-1955", "CVE-2012-1957", "CVE-2012-1958", "CVE-2012-1959", "CVE-2012-1960", "CVE-2012-1961", "CVE-2012-1962", "CVE-2012-1963", "CVE-2012-1967");
  script_tag(name:"creation_date", value:"2012-07-19 05:13:29 +0000 (Thu, 19 Jul 2012)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1510-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|11\.04|11\.10|12\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-1510-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1510-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1020198");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1024564");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the USN-1510-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Benoit Jacob, Jesse Ruderman, Christian Holler, Bill McCloskey, Brian Smith,
Gary Kwong, Christoph Diehl, Chris Jones, Brad Lassey, and Kyle Huey discovered
memory safety issues affecting Thunderbird. If the user were tricked into
opening a specially crafted page, an attacker could possibly exploit these to
cause a denial of service via application crash, or potentially execute code
with the privileges of the user invoking Thunderbird. (CVE-2012-1948,
CVE-2012-1949)

Abhishek Arya discovered four memory safety issues affecting Thunderbird. If
the user were tricked into opening a specially crafted page, an attacker could
possibly exploit these to cause a denial of service via application crash, or
potentially execute code with the privileges of the user invoking Thunderbird.
(CVE-2012-1951, CVE-2012-1952, CVE-2012-1953, CVE-2012-1954)

Mariusz Mlynski discovered that the address bar may be incorrectly updated.
Calls to history.forward and history.back could be used to navigate to a site
while the address bar still displayed the previous site. A remote attacker
could exploit this to conduct phishing attacks. (CVE-2012-1955)

Mario Heiderich discovered that HTML <embed> tags were not filtered out of the
HTML <description> of RSS feeds. A remote attacker could exploit this to
conduct cross-site scripting (XSS) attacks via javascript execution in the HTML
feed view. (CVE-2012-1957)

Arthur Gerkis discovered a use-after-free vulnerability. If the user were
tricked into opening a specially crafted page, an attacker could possibly
exploit this to cause a denial of service via application crash, or potentially
execute code with the privileges of the user invoking Thunderbird.
(CVE-2012-1958)

Bobby Holley discovered that same-compartment security wrappers (SCSW) could be
bypassed to allow XBL access. If the user were tricked into opening a specially
crafted page, an attacker could possibly exploit this to execute code with the
privileges of the user invoking Thunderbird. (CVE-2012-1959)

Tony Payne discovered an out-of-bounds memory read in Mozilla's color
management library (QCMS). If the user were tricked into opening a specially
crafted color profile, an attacker could possibly exploit this to cause a
denial of service via application crash. (CVE-2012-1960)

Frederic Buclin discovered that the X-Frame-Options header was ignored when its
value was specified multiple times. An attacker could exploit this to conduct
clickjacking attacks. (CVE-2012-1961)

Bill Keese discovered a memory corruption vulnerability. If the user were
tricked into opening a specially crafted page, an attacker could possibly
exploit this to cause a denial of service via application crash, or potentially
execute code with the privileges of the user invoking Thunderbird.
(CVE-2012-1962)

Karthikeyan Bhargavan discovered an information leakage vulnerability in the
Content Security Policy (CSP) 1.0 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Ubuntu 10.04, Ubuntu 11.04, Ubuntu 11.10, Ubuntu 12.04.");

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

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"14.0+build1-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"14.0+build1-0ubuntu0.11.04.1", rls:"UBUNTU11.04"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"14.0+build1-0ubuntu0.11.10.1", rls:"UBUNTU11.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"14.0+build1-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS"))) {
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
