# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842770");
  script_cve_id("CVE-2016-2804", "CVE-2016-2806", "CVE-2016-2807", "CVE-2016-2808", "CVE-2016-2811", "CVE-2016-2812", "CVE-2016-2814", "CVE-2016-2816", "CVE-2016-2817", "CVE-2016-2820");
  script_tag(name:"creation_date", value:"2016-05-19 03:21:16 +0000 (Thu, 19 May 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-04 16:29:49 +0000 (Wed, 04 May 2016)");

  script_name("Ubuntu: Security Advisory (USN-2936-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS|15\.10|16\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-2936-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2936-3");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1583389");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-2936-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-2936-1 fixed vulnerabilities in Firefox. The update caused an issue
where a device update POST request was sent every time about:preferences#sync
was shown. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Christian Holler, Tyson Smith, Phil Ringalda, Gary Kwong, Jesse Ruderman,
 Mats Palmgren, Carsten Book, Boris Zbarsky, David Bolter, Randell Jesup,
 Andrew McCreight, and Steve Fink discovered multiple memory safety issues
 in Firefox. If a user were tricked in to opening a specially crafted
 website, an attacker could potentially exploit these to cause a denial of
 service via application crash, or execute arbitrary code with the
 privileges of the user invoking Firefox. (CVE-2016-2804, CVE-2016-2806,
 CVE-2016-2807)

 An invalid write was discovered when using the JavaScript .watch() method in
 some circumstances. If a user were tricked in to opening a specially crafted
 website, an attacker could potentially exploit this to cause a denial of
 service via application crash, or execute arbitrary code with the
 privileges of the user invoking Firefox. (CVE-2016-2808)

 Looben Yang discovered a use-after-free and buffer overflow in service
 workers. If a user were tricked in to opening a specially crafted website,
 an attacker could potentially exploit these to cause a denial of service
 via application crash, or execute arbitrary code with the privileges of
 the user invoking Firefox. (CVE-2016-2811, CVE-2016-2812)

 Sascha Just discovered a buffer overflow in libstagefright in some
 circumstances. If a user were tricked in to opening a specially crafted
 website, an attacker could potentially exploit this to cause a denial of
 service via application crash, or execute arbitrary code with the
 privileges of the user invoking Firefox. (CVE-2016-2814)

 Muneaki Nishimura discovered that CSP is not applied correctly to web
 content sent with the multipart/x-mixed-replace MIME type. An attacker
 could potentially exploit this to conduct cross-site scripting (XSS)
 attacks when they would otherwise be prevented. (CVE-2016-2816)

 Muneaki Nishimura discovered that the chrome.tabs.update API for web
 extensions allows for navigation to javascript: URLs. A malicious
 extension could potentially exploit this to conduct cross-site scripting
 (XSS) attacks. (CVE-2016-2817)

 Mark Goodwin discovered that about:healthreport accepts certain events
 from any content present in the remote-report iframe. If another
 vulnerability allowed the injection of web content in the remote-report
 iframe, an attacker could potentially exploit this to change the user's
 sharing preferences. (CVE-2016-2820)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.10, Ubuntu 16.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"46.0.1+build1-0ubuntu0.12.04.2", rls:"UBUNTU12.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"46.0.1+build1-0ubuntu0.14.04.3", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU15.10") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"46.0.1+build1-0ubuntu0.15.10.2", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"46.0.1+build1-0ubuntu0.16.04.2", rls:"UBUNTU16.04 LTS"))) {
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
