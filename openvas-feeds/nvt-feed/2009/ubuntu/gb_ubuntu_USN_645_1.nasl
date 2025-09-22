# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840354");
  script_cve_id("CVE-2008-0016", "CVE-2008-3835", "CVE-2008-3836", "CVE-2008-3837", "CVE-2008-4058", "CVE-2008-4059", "CVE-2008-4060", "CVE-2008-4061", "CVE-2008-4062", "CVE-2008-4063", "CVE-2008-4064", "CVE-2008-4065", "CVE-2008-4066", "CVE-2008-4067", "CVE-2008-4068", "CVE-2008-4069");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-645-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(7\.04|7\.10|8\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-645-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-645-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox, firefox-3.0, xulrunner-1.9' package(s) announced via the USN-645-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Justin Schuh, Tom Cross and Peter Williams discovered errors in the
Firefox URL parsing routines. If a user were tricked into opening a
crafted hyperlink, an attacker could overflow a stack buffer and
execute arbitrary code. (CVE-2008-0016)

It was discovered that the same-origin check in Firefox could be
bypassed. If a user were tricked into opening a malicious website,
an attacker may be able to execute JavaScript in the context of a
different website. (CVE-2008-3835)

Several problems were discovered in the JavaScript engine. This
could allow an attacker to execute scripts from page content with
chrome privileges. (CVE-2008-3836)

Paul Nickerson discovered Firefox did not properly process mouse
click events. If a user were tricked into opening a malicious web
page, an attacker could move the content window, which could
potentially be used to force a user to perform unintended drag and
drop operations. (CVE-2008-3837)

Several problems were discovered in the browser engine. This could
allow an attacker to execute code with chrome privileges.
(CVE-2008-4058, CVE-2008-4059, CVE-2008-4060)

Drew Yao, David Maciejak and other Mozilla developers found several
problems in the browser engine of Firefox. If a user were tricked
into opening a malicious web page, an attacker could cause a denial
of service or possibly execute arbitrary code with the privileges
of the user invoking the program. (CVE-2008-4061, CVE-2008-4062,
CVE-2008-4063, CVE-2008-4064)

Dave Reed discovered a flaw in the JavaScript parsing code when
processing certain BOM characters. An attacker could exploit this
to bypass script filters and perform cross-site scripting attacks.
(CVE-2008-4065)

Gareth Heyes discovered a flaw in the HTML parser of Firefox. If a
user were tricked into opening a malicious web page, an attacker
could bypass script filtering and perform cross-site scripting
attacks. (CVE-2008-4066)

Boris Zbarsky and Georgi Guninski independently discovered flaws in
the resource: protocol. An attacker could exploit this to perform
directory traversal, read information about the system, and prompt
the user to save information in a file. (CVE-2008-4067,
CVE-2008-4068)

Billy Hoffman discovered a problem in the XBM decoder. If a user were
tricked into opening a malicious web page or XBM file, an attacker
may be able to cause a denial of service via application crash.
(CVE-2008-4069)");

  script_tag(name:"affected", value:"'firefox, firefox-3.0, xulrunner-1.9' package(s) on Ubuntu 7.04, Ubuntu 7.10, Ubuntu 8.04.");

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

if(release == "UBUNTU7.04") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"2.0.0.17+0nobinonly-0ubuntu0.7.4", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU7.10") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"2.0.0.17+1nobinonly-0ubuntu0.7.10", rls:"UBUNTU7.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"firefox-3.0", ver:"3.0.2+build6+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-1.9", ver:"1.9.0.2+build6+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS"))) {
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
