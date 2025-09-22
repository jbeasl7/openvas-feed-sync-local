# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841490");
  script_cve_id("CVE-2013-1682", "CVE-2013-1683", "CVE-2013-1684", "CVE-2013-1685", "CVE-2013-1686", "CVE-2013-1687", "CVE-2013-1688", "CVE-2013-1690", "CVE-2013-1692", "CVE-2013-1693", "CVE-2013-1694", "CVE-2013-1695", "CVE-2013-1696", "CVE-2013-1697", "CVE-2013-1698", "CVE-2013-1699");
  script_tag(name:"creation_date", value:"2013-06-27 04:31:51 +0000 (Thu, 27 Jun 2013)");
  script_version("2025-08-15T05:40:49+0000");
  script_tag(name:"last_modification", value:"2025-08-15 05:40:49 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-09 18:25:57 +0000 (Tue, 09 Jul 2024)");

  script_name("Ubuntu: Security Advisory (USN-1890-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|12\.10|13\.04)");

  script_xref(name:"Advisory-ID", value:"USN-1890-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1890-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1192913");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-1890-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple memory safety issues were discovered in Firefox. If the user were
tricked into opening a specially crafted page, an attacker could possibly
exploit these to cause a denial of service via application crash, or
potentially execute arbitrary code with the privileges of the user invoking
Firefox. (CVE-2013-1682, CVE-2013-1683)

Abhishek Arya discovered multiple use-after-free bugs. If the user were
tricked into opening a specially crafted page, an attacker could possibly
exploit these to execute arbitrary code with the privileges of the user
invoking Firefox. (CVE-2013-1684, CVE-2013-1685, CVE-2013-1686)

Mariusz Mlynski discovered that user defined code within the XBL scope of
an element could be made to bypass System Only Wrappers (SOW). An attacker
could potentially exploit this to execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2013-1687)

Mariusz Mlynski discovered that the profiler user interface incorrectly
handled data from the profiler. If the user examined profiler output
on a specially crafted page, an attacker could potentially exploit this to
execute arbitrary code with the privileges of the user invoking Firefox.
(CVE-2013-1688)

A crash was discovered when reloading a page that contained content using
the onreadystatechange event. An attacker could potentially exploit this
to execute arbitrary code with the privileges of the user invoking Firefox
(CVE-2013-1690)

Johnathan Kuskos discovered that Firefox sent data in the body of
XMLHttpRequest HEAD requests. An attacker could exploit this to conduct
Cross-Site Request Forgery (CSRF) attacks. (CVE-2013-1692)

Paul Stone discovered a timing flaw in the processing of SVG images with
filters. An attacker could exploit this to view sensitive information.
(CVE-2013-1693)

Boris Zbarsky discovered a flaw in PreserveWrapper. An attacker could
potentially exploit this to cause a denial of service via application
crash, or execute code with the privileges of the user invoking Firefox.
(CVE-2013-1694)

Bob Owen discovered that a sandboxed iframe could use a frame element
to bypass its own restrictions. (CVE-2013-1695)

Frederic Buclin discovered that the X-Frame-Options header is ignored
in multi-part responses. An attacker could potentially exploit this
to conduct clickjacking attacks. (CVE-2013-1696)

It was discovered that XrayWrappers could be bypassed to call
content-defined methods in certain circumstances. An attacker could
exploit this to cause undefined behaviour. (CVE-2013-1697)

Matt Wobensmith discovered that the getUserMedia permission dialog
displayed the wrong domain in certain circumstances. An attacker could
potentially exploit this to trick the user in to giving a malicious
site access to their microphone or camera. (CVE-2013-1698)

It was discovered that the measures for preventing homograph attacks
using Internationalized Domain Names (IDN) were not sufficient
for ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"22.0+build2-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU12.10") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"22.0+build2-0ubuntu0.12.10.1", rls:"UBUNTU12.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU13.04") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"22.0+build2-0ubuntu0.13.04.1", rls:"UBUNTU13.04"))) {
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
