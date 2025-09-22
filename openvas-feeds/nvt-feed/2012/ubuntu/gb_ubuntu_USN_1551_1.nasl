# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841128");
  script_cve_id("CVE-2012-1956", "CVE-2012-1970", "CVE-2012-1971", "CVE-2012-1972", "CVE-2012-1973", "CVE-2012-1974", "CVE-2012-1975", "CVE-2012-1976", "CVE-2012-3956", "CVE-2012-3957", "CVE-2012-3958", "CVE-2012-3959", "CVE-2012-3960", "CVE-2012-3961", "CVE-2012-3962", "CVE-2012-3963", "CVE-2012-3964", "CVE-2012-3966", "CVE-2012-3967", "CVE-2012-3968", "CVE-2012-3969", "CVE-2012-3970", "CVE-2012-3971", "CVE-2012-3972", "CVE-2012-3975", "CVE-2012-3978", "CVE-2012-3980");
  script_tag(name:"creation_date", value:"2012-09-04 06:06:38 +0000 (Tue, 04 Sep 2012)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1551-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|11\.04|11\.10|12\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-1551-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1551-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1042165");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the USN-1551-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Gary Kwong, Christian Holler, Jesse Ruderman, Steve Fink, Bob Clary, Andrew
Sutherland, Jason Smith, John Schoenick, Vladimir Vukicevic and Daniel
Holbert discovered memory safety issues affecting Thunderbird. If the user
were tricked into opening a specially crafted E-Mail, an attacker could
exploit these to cause a denial of service via application crash, or
potentially execute code with the privileges of the user invoking
Thunderbird. (CVE-2012-1970, CVE-2012-1971)

Abhishek Arya discovered multiple use-after-free vulnerabilities. If the
user were tricked into opening a specially crafted E-Mail, an attacker
could exploit these to cause a denial of service via application crash, or
potentially execute code with the privileges of the user invoking
Thunderbird. (CVE-2012-1972, CVE-2012-1973, CVE-2012-1974, CVE-2012-1975,
CVE-2012-1976, CVE-2012-3956, CVE-2012-3957, CVE-2012-3958, CVE-2012-3959,
CVE-2012-3960, CVE-2012-3961, CVE-2012-3962, CVE-2012-3963, CVE-2012-3964)

Mariusz Mlynsk discovered that it is possible to shadow the location object
using Object.defineProperty. This could potentially result in a cross-site
scripting (XSS) attack against plugins. With cross-site scripting
vulnerabilities, if a user were tricked into viewing a specially crafted
E-Mail, a remote attacker could exploit this to modify the contents or
steal confidential data within the same domain. (CVE-2012-1956)

Frederic Hoguin discovered that bitmap format images with a negative height
could potentially result in memory corruption. If the user were tricked
into opening a specially crafted image, an attacker could exploit this to
cause a denial of service via application crash, or potentially execute
code with the privileges of the user invoking Thunderbird. (CVE-2012-3966)

It was discovered that Thunderbird's WebGL implementation was vulnerable to
multiple memory safety issues. If the user were tricked into opening a
specially crafted E-Mail, an attacker could exploit these to cause a denial
of service via application crash, or potentially execute code with the
privileges of the user invoking Thunderbird. (CVE-2012-3967, CVE-2012-3968)

Arthur Gerkis discovered multiple memory safety issues in Thunderbird's
Scalable Vector Graphics (SVG) implementation. If the user were tricked
into opening a specially crafted image, an attacker could exploit these to
cause a denial of service via application crash, or potentially execute
code with the privileges of the user invoking Thunderbird. (CVE-2012-3969,
CVE-2012-3970)

Christoph Diehl discovered multiple memory safety issues in the bundled
Graphite 2 library. If the user were tricked into opening a specially
crafted E-Mail, an attacker could exploit these to cause a denial of
service via application crash, or potentially execute code with the
privileges of the user invoking Thunderbird. (CVE-2012-3971)

Nicolas Gregoire discovered an out-of-bounds read ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"15.0+build1-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"15.0+build1-0ubuntu0.11.04.1", rls:"UBUNTU11.04"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"15.0+build1-0ubuntu0.11.10.1", rls:"UBUNTU11.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"15.0+build1-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS"))) {
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
