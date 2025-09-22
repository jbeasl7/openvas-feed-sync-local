# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842931");
  script_cve_id("CVE-2016-5250", "CVE-2016-5257", "CVE-2016-5270", "CVE-2016-5272", "CVE-2016-5274", "CVE-2016-5276", "CVE-2016-5277", "CVE-2016-5278", "CVE-2016-5280", "CVE-2016-5281", "CVE-2016-5284");
  script_tag(name:"creation_date", value:"2016-11-08 10:22:48 +0000 (Tue, 08 Nov 2016)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-09-23 14:13:35 +0000 (Fri, 23 Sep 2016)");

  script_name("Ubuntu: Security Advisory (USN-3112-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS|16\.04\ LTS|16\.10)");

  script_xref(name:"Advisory-ID", value:"USN-3112-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3112-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the USN-3112-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Catalin Dumitru discovered that URLs of resources loaded after a
navigation start could be leaked to the following page via the Resource
Timing API. If a user were tricked in to opening a specially crafted
website in a browsing context, an attacker could potentially exploit this
to obtain sensitive information. (CVE-2016-5250)

Christoph Diehl, Andrew McCreight, Dan Minor, Byron Campen, Jon Coppeard,
Steve Fink, Tyson Smith, and Carsten Book discovered multiple memory
safety issues in Thunderbird. If a user were tricked in to opening a
specially crafted message, an attacker could potentially exploit these to
cause a denial of service via application crash, or execute arbitrary
code. (CVE-2016-5257)

Atte Kettunen discovered a heap buffer overflow during text conversion
with some unicode characters. If a user were tricked in to opening a
specially crafted message, an attacker could potentially exploit this to
cause a denial of service via application crash, or execute arbitrary
code. (CVE-2016-5270)

Abhishek Arya discovered a bad cast when processing layout with input
elements in some circumstances. If a user were tricked in to opening a
specially crafted website in a browsing context, an attacker could
potentially exploit this to cause a denial of service via application
crash, or execute arbitrary code. (CVE-2016-5272)

A use-after-free was discovered in web animations during restyling. If a
user were tricked in to opening a specially crafted website in a browsing
context, an attacker could potentially exploit this to cause a denial of
service via application crash, or execute arbitrary code. (CVE-2016-5274)

A use-after-free was discovered in accessibility. If a user were tricked
in to opening a specially crafted website in a browsing context, an
attacker could potentially exploit this to cause a denial of service via
application crash, or execute arbitrary code. (CVE-2016-5276)

A use-after-free was discovered in web animations when destroying a
timeline. If a user were tricked in to opening a specially crafted
website in a browsing context, an attacker could potentially exploit this
to cause a denial of service via application crash, or execute arbitrary
code. (CVE-2016-5277)

A buffer overflow was discovered when encoding image frames to images in
some circumstances. If a user were tricked in to opening a specially
crafted message, an attacker could potentially exploit this to cause a
denial of service via application crash, or execute arbitrary code.
(CVE-2016-5278)

Mei Wang discovered a use-after-free when changing text direction. If a
user were tricked in to opening a specially crafted website in a browsing
context, an attacker could potentially exploit this to cause a denial of
service via application crash, or execute arbitrary code. (CVE-2016-5280)

Brian Carpenter discovered a use-after-free when manipulating SVG content
in some circumstances. If a user ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 16.04, Ubuntu 16.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"1:45.4.0+build1-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"1:45.4.0+build1-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"1:45.4.0+build1-0ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"1:45.4.0+build1-0ubuntu0.16.10.1", rls:"UBUNTU16.10"))) {
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
