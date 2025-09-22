# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840223");
  script_cve_id("CVE-2008-0017", "CVE-2008-4582", "CVE-2008-5012", "CVE-2008-5013", "CVE-2008-5014", "CVE-2008-5015", "CVE-2008-5016", "CVE-2008-5017", "CVE-2008-5018", "CVE-2008-5019", "CVE-2008-5021", "CVE-2008-5022", "CVE-2008-5023", "CVE-2008-5024");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-667-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(6\.06\ LTS|7\.10|8\.04\ LTS|8\.10)");

  script_xref(name:"Advisory-ID", value:"USN-667-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-667-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox, firefox-3.0, xulrunner-1.9' package(s) announced via the USN-667-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Liu Die Yu discovered an information disclosure vulnerability in Firefox
when using saved .url shortcut files. If a user were tricked into
downloading a crafted .url file and a crafted HTML file, an attacker
could steal information from the user's cache. (CVE-2008-4582)

Georgi Guninski, Michal Zalewsk and Chris Evans discovered that the
same-origin check in Firefox could be bypassed. If a user were tricked
into opening a malicious website, an attacker could obtain private
information from data stored in the images, or discover information
about software on the user's computer. This issue only affects Firefox 2.
(CVE-2008-5012)

It was discovered that Firefox did not properly check if the Flash
module was properly unloaded. By tricking a user into opening a crafted
SWF file, an attacker could cause Firefox to crash and possibly execute
arbitrary code with user privileges. This issue only affects Firefox 2.
(CVE-2008-5013)

Jesse Ruderman discovered that Firefox did not properly guard locks on
non-native objects. If a user were tricked into opening a malicious
website, an attacker could cause a browser crash and possibly execute
arbitrary code with user privileges. This issue only affects Firefox 2.
(CVE-2008-5014)

Luke Bryan discovered that Firefox sometimes opened file URIs with
chrome privileges. If a user saved malicious code locally, then opened
the file in the same tab as a privileged document, an attacker could
run arbitrary JavaScript code with chrome privileges. This issue only
affects Firefox 3.0. (CVE-2008-5015)

Several problems were discovered in the browser, layout and JavaScript
engines. These problems could allow an attacker to crash the browser
and possibly execute arbitrary code with user privileges.
(CVE-2008-5016, CVE-2008-5017, CVE-2008-5018)

David Bloom discovered that the same-origin check in Firefox could be
bypassed by utilizing the session restore feature. An attacker could
exploit this to run JavaScript in the context of another site or
execute arbitrary JavaScript code with chrome privileges.
(CVE-2008-5019)

Justin Schuh discovered a flaw in Firefox's mime-type parsing. If a
user were tricked into opening a malicious website, an attacker could
send a crafted header in the HTTP index response, causing a browser
crash and execute arbitrary code with user privileges. (CVE-2008-0017)

A flaw was discovered in Firefox's DOM constructing code. If a user
were tricked into opening a malicious website, an attacker could
cause the browser to crash and potentially execute arbitrary code with
user privileges. (CVE-2008-5021)

It was discovered that the same-origin check in Firefox could be
bypassed. If a user were tricked into opening a malicious website, an
attacker could execute JavaScript in the context of a different website.
(CVE-2008-5022)

Collin Jackson discovered various flaws in Firefox when processing
stylesheets which allowed JavaScript to ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'firefox, firefox-3.0, xulrunner-1.9' package(s) on Ubuntu 6.06, Ubuntu 7.10, Ubuntu 8.04, Ubuntu 8.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"1.5.dfsg+1.5.0.15~prepatch080614h-0ubuntu1", rls:"UBUNTU6.06 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"2.0.0.18+nobinonly-0ubuntu0.7.10", rls:"UBUNTU7.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"firefox-3.0", ver:"3.0.4+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-1.9", ver:"1.9.0.4+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"abrowser", ver:"3.0.4+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-3.0", ver:"3.0.4+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-1.9", ver:"1.9.0.4+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10"))) {
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
