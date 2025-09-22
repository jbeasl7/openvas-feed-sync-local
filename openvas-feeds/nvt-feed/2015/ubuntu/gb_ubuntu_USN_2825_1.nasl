# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842556");
  script_cve_id("CVE-2015-6765", "CVE-2015-6766", "CVE-2015-6767", "CVE-2015-6768", "CVE-2015-6769", "CVE-2015-6770", "CVE-2015-6771", "CVE-2015-6772", "CVE-2015-6773", "CVE-2015-6777", "CVE-2015-6782", "CVE-2015-6784", "CVE-2015-6785", "CVE-2015-6786", "CVE-2015-6787", "CVE-2015-8478");
  script_tag(name:"creation_date", value:"2015-12-11 04:47:48 +0000 (Fri, 11 Dec 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2825-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|15\.04|15\.10)");

  script_xref(name:"Advisory-ID", value:"USN-2825-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2825-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'oxide-qt' package(s) announced via the USN-2825-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple use-after-free bugs were discovered in the application cache
implementation in Chromium. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit these to
cause a denial of service via application crash, or execute arbitrary code
with the privileges of the user invoking the program. (CVE-2015-6765,
CVE-2015-6766, CVE-2015-6767)

Several security issues were discovered in the DOM implementation in
Chromium. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit these to bypass same
origin restrictions. (CVE-2015-6768, CVE-2015-6770)

A security issue was discovered in the provisional-load commit
implementation in Chromium. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this to
bypass same origin restrictions. (CVE-2015-6769)

An out-of-bounds read was discovered in the array map and filter
operations in V8 in some circumstances. If a user were tricked in to
opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service via renderer crash.
(CVE-2015-6771)

It was discovered that the DOM implementation in Chromium does not prevent
javascript: URL navigation while a document is being detached. If a user
were tricked in to opening a specially crafted website, an attacker could
potentially exploit this to bypass same origin restrictions.
(CVE-2015-6772)

An out-of bounds read was discovered in Skia in some circumstances. If a
user were tricked in to opening a specially crafted website, an attacker
could potentially exploit this to cause a denial of service via renderer
crash. (CVE-2015-6773)

A use-after-free was discovered in the DOM implementation in Chromium. If
a user were tricked in to opening a specially crafted website, an attacker
could potentially exploit this to cause a denial of service via renderer
crash or execute arbitrary code with the privileges of the sandboxed
render process. (CVE-2015-6777)

It was discovered that the Document::open function in Chromium did not
ensure that page-dismissal event handling is compatible with modal dialog
blocking. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to spoof application
UI content. (CVE-2015-6782)

It was discovered that the page serializer in Chromium mishandled MOTW
comments for URLs in some circumstances. An attacker could potentially
exploit this to inject HTML content. (CVE-2015-6784)

It was discovered that the Content Security Policy (CSP) implementation
in Chromium accepted an x.y hostname as a match for a *.x.y pattern. An
attacker could potentially exploit this to bypass intended access
restrictions. (CVE-2015-6785)

It was discovered that the Content Security Policy (CSP) implementation
in Chromium accepted blob:, data: and filesystem: URLs as ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'oxide-qt' package(s) on Ubuntu 14.04, Ubuntu 15.04, Ubuntu 15.10.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"liboxideqtcore0", ver:"1.11.3-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"liboxideqtcore0", ver:"1.11.3-0ubuntu0.15.04.1", rls:"UBUNTU15.04"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"liboxideqtcore0", ver:"1.11.3-0ubuntu0.15.10.1", rls:"UBUNTU15.10"))) {
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
