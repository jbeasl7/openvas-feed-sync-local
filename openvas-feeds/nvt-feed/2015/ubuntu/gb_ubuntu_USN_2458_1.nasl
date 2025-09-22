# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842066");
  script_cve_id("CVE-2014-8634", "CVE-2014-8635", "CVE-2014-8636", "CVE-2014-8637", "CVE-2014-8638", "CVE-2014-8639", "CVE-2014-8640", "CVE-2014-8641", "CVE-2014-8642");
  script_tag(name:"creation_date", value:"2015-01-23 11:59:07 +0000 (Fri, 23 Jan 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2458-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS|14\.10)");

  script_xref(name:"Advisory-ID", value:"USN-2458-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2458-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-2458-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Christian Holler, Patrick McManus, Christoph Diehl, Gary Kwong, Jesse
Ruderman, Byron Campen, Terrence Cole, and Nils Ohlmeier discovered
multiple memory safety issues in Firefox. If a user were tricked in to
opening a specially crafted website, an attacker could potentially exploit
these to cause a denial of service via application crash, or execute
arbitrary code with the privileges of the user invoking Firefox.
(CVE-2014-8634, CVE-2014-8635)

Bobby Holley discovered that some DOM objects with certain properties
can bypass XrayWrappers in some circumstances. If a user were tricked in
to opening a specially crafted website, an attacker could potentially
exploit this to bypass security restrictions. (CVE-2014-8636)

Michal Zalewski discovered a use of uninitialized memory when rendering
malformed bitmap images on a canvas element. If a user were tricked in to
opening a specially crafted website, an attacker could potentially
exploit this to steal confidential information. (CVE-2014-8637)

Muneaki Nishimura discovered that requests from navigator.sendBeacon()
lack an origin header. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this to conduct
cross-site request forgery (XSRF) attacks. (CVE-2014-8638)

Xiaofeng Zheng discovered that a web proxy returning a 407 response
could inject cookies in to the originally requested domain. If a user
connected to a malicious web proxy, an attacker could potentially exploit
this to conduct session-fixation attacks. (CVE-2014-8639)

Holger Fuhrmannek discovered a crash in Web Audio while manipulating
timelines. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial
of service. (CVE-2014-8640)

Mitchell Harper discovered a use-after-free in WebRTC. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the user invoking
Firefox. (CVE-2014-8641)

Brian Smith discovered that OCSP responses would fail to verify if signed
by a delegated OCSP responder certificate with the id-pkix-ocsp-nocheck
extension, potentially allowing a user to connect to a site with a revoked
certificate. (CVE-2014-8642)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 14.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"35.0+build3-0ubuntu0.12.04.2", rls:"UBUNTU12.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"35.0+build3-0ubuntu0.14.04.2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU14.10") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"35.0+build3-0ubuntu0.14.10.2", rls:"UBUNTU14.10"))) {
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
