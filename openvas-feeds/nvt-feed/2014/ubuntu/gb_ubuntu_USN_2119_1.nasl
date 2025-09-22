# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841720");
  script_cve_id("CVE-2013-6674", "CVE-2014-1477", "CVE-2014-1479", "CVE-2014-1481", "CVE-2014-1482", "CVE-2014-1486", "CVE-2014-1487", "CVE-2014-1490", "CVE-2014-1491");
  script_tag(name:"creation_date", value:"2014-02-20 09:47:29 +0000 (Thu, 20 Feb 2014)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2014-02-06 19:14:22 +0000 (Thu, 06 Feb 2014)");

  script_name("Ubuntu: Security Advisory (USN-2119-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|12\.10|13\.10)");

  script_xref(name:"Advisory-ID", value:"USN-2119-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2119-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1274894");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the USN-2119-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Christian Holler, Terrence Cole, Jesse Ruderman, Gary Kwong, Eric
Rescorla, Jonathan Kew, Dan Gohman, Ryan VanderMeulen and Sotaro Ikeda
discovered multiple memory safety issues in Thunderbird. If a user were
tricked in to opening a specially crafted message with scripting enabled,
an attacker could potentially exploit these to cause a denial of service
via application crash, or execute arbitrary code with the privileges of
the user invoking Thunderbird. (CVE-2014-1477)

Cody Crews discovered a method to bypass System Only Wrappers. If a user
had enabled scripting, an attacker could potentially exploit this to steal
confidential data or execute code with the privileges of the user invoking
Thunderbird. (CVE-2014-1479)

Fredrik Lonnqvist discovered a use-after-free in Thunderbird. If a user
had enabled scripting, an attacker could potentially exploit this to cause
a denial of service via application crash, or execute arbitrary code with
the privileges of the user invoking Thunderbird. (CVE-2014-1482)

Arthur Gerkis discovered a use-after-free in Thunderbird. If a user had
enabled scripting, an attacker could potentially exploit this to cause a
denial of service via application crash, or execute arbitrary code with
the privileges of the user invoking Thunderbird. (CVE-2014-1486)

Masato Kinugawa discovered a cross-origin information leak in web worker
error messages. If a user had enabled scripting, an attacker could
potentially exploit this to steal confidential information.
(CVE-2014-1487)

Several issues were discovered with ticket handling in NSS. An attacker
could potentially exploit these to cause a denial of service or bypass
cryptographic protection mechanisms. (CVE-2014-1490, CVE-2014-1491)

Boris Zbarsky discovered that security restrictions on window objects
could be bypassed under certain circumstances. (CVE-2014-1481)

Fabian Cuchietti and Ateeq ur Rehman Khan discovered that it was possible
to bypass Javascript execution restrictions when replying to or forwarding
mail messages in certain circumstances. An attacker could potentially
exploit this to steal confidential information or modify message content.
(CVE-2013-6674)");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.10.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"1:24.3.0+build2-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"1:24.3.0+build2-0ubuntu0.12.10.1", rls:"UBUNTU12.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU13.10") {

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"1:24.3.0+build2-0ubuntu0.13.10.1", rls:"UBUNTU13.10"))) {
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
