# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840640");
  script_cve_id("CVE-2011-0065", "CVE-2011-0066", "CVE-2011-0067", "CVE-2011-0069", "CVE-2011-0070", "CVE-2011-0071", "CVE-2011-0072", "CVE-2011-0073", "CVE-2011-0074", "CVE-2011-0075", "CVE-2011-0077", "CVE-2011-0078", "CVE-2011-0080", "CVE-2011-0081", "CVE-2011-1202");
  script_tag(name:"creation_date", value:"2011-05-10 12:04:15 +0000 (Tue, 10 May 2011)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1112-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|10\.10|8\.04\ LTS|9\.10)");

  script_xref(name:"Advisory-ID", value:"USN-1112-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1112-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox, firefox-3.0, firefox-3.5, xulrunner-1.9.2' package(s) announced via the USN-1112-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was a vulnerability in the memory handling of
certain types of content. An attacker could exploit this to possibly run
arbitrary code as the user running Firefox. (CVE-2011-0081)

It was discovered that Firefox incorrectly handled certain JavaScript
requests. An attacker could exploit this to possibly run arbitrary code as
the user running Firefox. (CVE-2011-0069)

Ian Beer discovered a vulnerability in the memory handling of a certain
types of documents. An attacker could exploit this to possibly run
arbitrary code as the user running Firefox. (CVE-2011-0070)

Bob Clary, Henri Sivonen, Marco Bonardo, Mats Palmgren and Jesse Ruderman
discovered several memory vulnerabilities. An attacker could exploit these
to possibly run arbitrary code as the user running Firefox. (CVE-2011-0080)

Aki Helin discovered multiple vulnerabilities in the HTML rendering code.
An attacker could exploit these to possibly run arbitrary code as the user
running Firefox. (CVE-2011-0074, CVE-2011-0075)

Ian Beer discovered multiple overflow vulnerabilities. An attacker could
exploit these to possibly run arbitrary code as the user running Firefox.
(CVE-2011-0077, CVE-2011-0078)

Martin Barbella discovered a memory vulnerability in the handling of
certain DOM elements. An attacker could exploit this to possibly run
arbitrary code as the user running Firefox. (CVE-2011-0072)

It was discovered that there were use-after-free vulnerabilities in
Firefox's mChannel and mObserverList objects. An attacker could exploit
these to possibly run arbitrary code as the user running Firefox.
(CVE-2011-0065, CVE-2011-0066)

It was discovered that there was a vulnerability in the handling of the
nsTreeSelection element. An attacker serving malicious content could
exploit this to possibly run arbitrary code as the user running Firefox.
(CVE-2011-0073)

Paul Stone discovered a vulnerability in the handling of Java applets. An
attacker could use this to mimic interaction with form autocomplete
controls and steal entries from the form history. (CVE-2011-0067)

Soroush Dalili discovered a vulnerability in the resource: protocol. This
could potentially allow an attacker to load arbitrary files that were
accessible to the user running Firefox. (CVE-2011-0071)

Chris Evans discovered a vulnerability in Firefox's XSLT generate-id()
function. An attacker could possibly use this vulnerability to make other
attacks more reliable. (CVE-2011-1202)");

  script_tag(name:"affected", value:"'firefox, firefox-3.0, firefox-3.5, xulrunner-1.9.2' package(s) on Ubuntu 8.04, Ubuntu 9.10, Ubuntu 10.04, Ubuntu 10.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"3.6.17+build3+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-1.9.2", ver:"1.9.2.17+build3+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU10.10") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"3.6.17+build3+nobinonly-0ubuntu0.10.10.1", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-1.9.2", ver:"1.9.2.17+build3+nobinonly-0ubuntu0.10.10.1", rls:"UBUNTU10.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"3.6.17+build3+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-1.9.2", ver:"1.9.2.17+build3+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU9.10") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"3.6.17+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-1.9.2", ver:"1.9.2.17+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10"))) {
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
