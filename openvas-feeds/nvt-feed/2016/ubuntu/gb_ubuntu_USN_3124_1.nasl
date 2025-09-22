# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842953");
  script_cve_id("CVE-2016-5289", "CVE-2016-5290", "CVE-2016-5291", "CVE-2016-5292", "CVE-2016-5296", "CVE-2016-5297", "CVE-2016-9063", "CVE-2016-9064", "CVE-2016-9066", "CVE-2016-9067", "CVE-2016-9068", "CVE-2016-9069", "CVE-2016-9070", "CVE-2016-9071", "CVE-2016-9073", "CVE-2016-9075", "CVE-2016-9076", "CVE-2016-9077");
  script_tag(name:"creation_date", value:"2016-11-19 04:36:56 +0000 (Sat, 19 Nov 2016)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-08 14:42:38 +0000 (Wed, 08 Aug 2018)");

  script_name("Ubuntu: Security Advisory (USN-3124-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS|16\.04\ LTS|16\.10)");

  script_xref(name:"Advisory-ID", value:"USN-3124-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3124-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-3124-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Christian Holler, Andrew McCreight, Dan Minor, Tyson Smith, Jon Coppeard,
Jan-Ivar Bruaroey, Jesse Ruderman, Markus Stange, Olli Pettay, Ehsan
Akhgari, Gary Kwong, Tooru Fujisawa, and Randell Jesup discovered multiple
memory safety issues in Firefox. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit these to
cause a denial of service via application crash, or execute arbitrary
code. (CVE-2016-5289, CVE-2016-5290)

A same-origin policy bypass was discovered with local HTML files in some
circumstances. An attacker could potentially exploit this to obtain
sensitive information. (CVE-2016-5291)

A crash was discovered when parsing URLs in some circumstances. If a user
were tricked in to opening a specially crafted website, an attacker could
potentially exploit this to execute arbitrary code. (CVE-2016-5292)

A heap buffer-overflow was discovered in Cairo when processing SVG
content. If a user were tricked in to opening a specially crafted website,
an attacker could potentially exploit this to cause a denial of service
via application crash, or execute arbitrary code. (CVE-2016-5296)

An error was discovered in argument length checking in Javascript. If a
user were tricked in to opening a specially crafted website, an attacker
could potentially exploit this to cause a denial of service via
application crash, or execute arbitrary code. (CVE-2016-5297)

An integer overflow was discovered in the Expat library. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service via application
crash. (CVE-2016-9063)

It was discovered that addon updates failed to verify that the addon ID
inside the signed package matched the ID of the addon being updated.
An attacker that could perform a machine-in-the-middle (MITM) attack could
potentially exploit this to provide malicious addon updates.
(CVE-2016-9064)

A buffer overflow was discovered in nsScriptLoadHandler. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service via application
crash, or execute arbitrary code. (CVE-2016-9066)

2 use-after-free bugs were discovered during DOM operations in some
circumstances. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit these to cause a denial of
service via application crash, or execute arbitrary code. (CVE-2016-9067,
CVE-2016-9069)

A heap use-after-free was discovered during web animations in some
circumstances. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial of
service via application crash, or execute arbitrary code. (CVE-2016-9068)

It was discovered that a page loaded in to the sidebar through a bookmark
could reference a privileged chrome window. ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 16.04, Ubuntu 16.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"50.0+build2-0ubuntu0.12.04.2", rls:"UBUNTU12.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"50.0+build2-0ubuntu0.14.04.2", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"50.0+build2-0ubuntu0.16.04.2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.10") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"50.0+build2-0ubuntu0.16.10.2", rls:"UBUNTU16.10"))) {
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
