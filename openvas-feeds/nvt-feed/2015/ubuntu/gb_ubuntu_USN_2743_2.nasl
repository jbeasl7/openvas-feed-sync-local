# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842457");
  script_cve_id("CVE-2015-4500", "CVE-2015-4501", "CVE-2015-4502", "CVE-2015-4504", "CVE-2015-4506", "CVE-2015-4507", "CVE-2015-4508", "CVE-2015-4509", "CVE-2015-4510");
  script_tag(name:"creation_date", value:"2015-09-24 05:27:37 +0000 (Thu, 24 Sep 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2743-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS|15\.04)");

  script_xref(name:"Advisory-ID", value:"USN-2743-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2743-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1498681");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ubufox' package(s) announced via the USN-2743-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-2743-1 fixed vulnerabilities in Firefox. This update provides the
corresponding update for Ubufox.

Original advisory details:

 Andrew Osmond, Olli Pettay, Andrew Sutherland, Christian Holler, David
 Major, Andrew McCreight, Cameron McCormack, Bob Clary and Randell Jesup
 discovered multiple memory safety issues in Firefox. If a user were
 tricked in to opening a specially crafted website, an attacker could
 potentially exploit these to cause a denial of service via application
 crash, or execute arbitrary code with the privileges of the user invoking
 Firefox. (CVE-2015-4500, CVE-2015-4501)

 Andre Bargull discovered that when a web page creates a scripted proxy
 for the window with a handler defined a certain way, a reference to the
 inner window will be passed, rather than that of the outer window.
 (CVE-2015-4502)

 Felix Grobert discovered an out-of-bounds read in the QCMS color
 management library in some circumstances. If a user were tricked in to
 opening a specially crafted website, an attacker could potentially exploit
 this to cause a denial of service via application crash, or obtain
 sensitive information. (CVE-2015-4504)

 Khalil Zhani discovered a buffer overflow when parsing VP9 content in some
 circumstances. If a user were tricked in to opening a specially crafted
 website, an attacker could potentially exploit this to cause a denial of
 service via application crash, or execute arbitrary code with the
 privileges of the user invoking Firefox. (CVE-2015-4506)

 Spandan Veggalam discovered a crash while using the debugger API in some
 circumstances. If a user were tricked in to opening a specially crafted
 website whilst using the debugger, an attacker could potentially exploit
 this to execute arbitrary code with the privileges of the user invoking
 Firefox. (CVE-2015-4507)

 Juho Nurminen discovered that the URL bar could display the wrong URL in
 reader mode in some circumstances. If a user were tricked in to opening a
 specially crafted website, an attacker could potentially exploit this to
 conduct URL spoofing attacks. (CVE-2015-4508)

 A use-after-free was discovered when manipulating HTML media content in
 some circumstances. If a user were tricked in to opening a specially
 crafted website, an attacker could potentially exploit this to cause a
 denial of service via application crash, or execute arbitrary code with
 the privileges of the user invoking Firefox. (CVE-2015-4509)

 Looben Yang discovered a use-after-free when using a shared worker with
 IndexedDB in some circumstances. If a user were tricked in to opening a
 specially crafted website, an attacker could potentially exploit this to
 cause a denial of service via application crash, or execute arbitrary code
 with the privileges of the user invoking Firefox. (CVE-2015-4510)

 Francisco Alonso discovered an out-of-bounds read during 2D canvas
 rendering in some circumstances. If a ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ubufox' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"xul-ext-ubufox", ver:"3.2-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"xul-ext-ubufox", ver:"3.2-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU15.04") {

  if(!isnull(res = isdpkgvuln(pkg:"xul-ext-ubufox", ver:"3.2-0ubuntu0.15.04.1", rls:"UBUNTU15.04"))) {
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
