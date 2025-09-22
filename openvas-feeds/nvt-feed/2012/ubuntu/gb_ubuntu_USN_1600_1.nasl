# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841181");
  script_cve_id("CVE-2012-3982", "CVE-2012-3983", "CVE-2012-3984", "CVE-2012-3985", "CVE-2012-3986", "CVE-2012-3988", "CVE-2012-3989", "CVE-2012-3990", "CVE-2012-3991", "CVE-2012-3992", "CVE-2012-3993", "CVE-2012-3994", "CVE-2012-3995", "CVE-2012-4179", "CVE-2012-4180", "CVE-2012-4181", "CVE-2012-4182", "CVE-2012-4183", "CVE-2012-4184", "CVE-2012-4185", "CVE-2012-4186", "CVE-2012-4187", "CVE-2012-4188");
  script_tag(name:"creation_date", value:"2012-10-11 04:34:22 +0000 (Thu, 11 Oct 2012)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1600-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|11\.04|11\.10|12\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-1600-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1600-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-1600-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Henrik Skupin, Jesse Ruderman, Christian Holler, Soroush Dalili and others
discovered several memory corruption flaws in Firefox. If a user were
tricked into opening a specially crafted web page, a remote attacker could
cause Firefox to crash or potentially execute arbitrary code as the user
invoking the program. (CVE-2012-3982, CVE-2012-3983, CVE-2012-3988,
CVE-2012-3989)

David Bloom and Jordi Chancel discovered that Firefox did not always
properly handle the <select> element. A remote attacker could exploit this
to conduct URL spoofing and clickjacking attacks. (CVE-2012-3984)

Collin Jackson discovered that Firefox did not properly follow the HTML5
specification for document.domain behavior. A remote attacker could exploit
this to conduct cross-site scripting (XSS) attacks via javascript
execution. (CVE-2012-3985)

Johnny Stenback discovered that Firefox did not properly perform security
checks on test methods for DOMWindowUtils. (CVE-2012-3986)

Alice White discovered that the security checks for GetProperty could be
bypassed when using JSAPI. If a user were tricked into opening a specially
crafted web page, a remote attacker could exploit this to execute arbitrary
code as the user invoking the program. (CVE-2012-3991)

Mariusz Mlynski discovered a history state error in Firefox. A remote
attacker could exploit this to spoof the location property to inject script
or intercept posted data. (CVE-2012-3992)

Mariusz Mlynski and others discovered several flaws in Firefox that allowed
a remote attacker to conduct cross-site scripting (XSS) attacks.
(CVE-2012-3993, CVE-2012-3994, CVE-2012-4184)

Abhishek Arya, Atte Kettunen and others discovered several memory flaws in
Firefox when using the Address Sanitizer tool. If a user were tricked into
opening a specially crafted web page, a remote attacker could cause Firefox
to crash or potentially execute arbitrary code as the user invoking the
program. (CVE-2012-3990, CVE-2012-3995, CVE-2012-4179, CVE-2012-4180,
CVE-2012-4181, CVE-2012-4182, CVE-2012-4183, CVE-2012-4185, CVE-2012-4186,
CVE-2012-4187, CVE-2012-4188)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 10.04, Ubuntu 11.04, Ubuntu 11.10, Ubuntu 12.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"16.0+build1-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"16.0+build1-0ubuntu0.11.04.1", rls:"UBUNTU11.04"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"16.0+build1-0ubuntu0.11.10.1", rls:"UBUNTU11.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"16.0+build1-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS"))) {
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
