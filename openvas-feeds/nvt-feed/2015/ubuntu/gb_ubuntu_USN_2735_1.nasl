# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842433");
  script_cve_id("CVE-2015-1291", "CVE-2015-1292", "CVE-2015-1293", "CVE-2015-1294", "CVE-2015-1299", "CVE-2015-1300", "CVE-2015-1301", "CVE-2015-1332");
  script_tag(name:"creation_date", value:"2015-09-09 04:28:07 +0000 (Wed, 09 Sep 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-10 13:52:46 +0000 (Thu, 10 Aug 2017)");

  script_name("Ubuntu: Security Advisory (USN-2735-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|15\.04)");

  script_xref(name:"Advisory-ID", value:"USN-2735-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2735-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1470905");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'oxide-qt' package(s) announced via the USN-2735-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the DOM tree could be corrupted during parsing in
some circumstances. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this to bypass
same-origin restrictions or cause a denial of service. (CVE-2015-1291)

An issue was discovered in NavigatorServiceWorker::serviceWorker in Blink.
If a user were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to bypass same-origin
restrictions. (CVE-2015-1292)

An issue was discovered in the DOM implementation in Blink. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit this to bypass same-origin restrictions.
(CVE-2015-1293)

A use-after-free was discovered in Skia. If a user were tricked in to
opening a specially crafted website, an attacker could potentially exploit
this to cause a denial of service via renderer crash, or execute arbitrary
code with the privileges of the sandboxed render process. (CVE-2015-1294)

A use-after-free was discovered in the shared-timer implementation in
Blink. If a user were tricked in to opening a specially crafted website,
an attacker could potentially exploit this to cause a denial of service
via renderer crash, or execute arbitrary code with the privileges of the
sandboxed render process. (CVE-2015-1299)

It was discovered that the availability of iframe Resource Timing API
times was not properly restricted in some circumstances. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit this to obtain sensitive information. (CVE-2015-1300)

Multiple security issues were discovered in Chromium. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to read uninitialized memory, cause a denial
of service via application crash or execute arbitrary code with the
privileges of the user invoking the program. (CVE-2015-1301)

A heap corruption issue was discovered in oxide::JavaScriptDialogManager.
If a user were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to cause a denial of service via
application crash, or execute arbitrary code with the privileges of the
user invoking the program. (CVE-2015-1332)");

  script_tag(name:"affected", value:"'oxide-qt' package(s) on Ubuntu 14.04, Ubuntu 15.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"liboxideqtcore0", ver:"1.9.1-0ubuntu0.14.04.2", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"liboxideqtcore0", ver:"1.9.1-0ubuntu0.15.04.1", rls:"UBUNTU15.04"))) {
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
