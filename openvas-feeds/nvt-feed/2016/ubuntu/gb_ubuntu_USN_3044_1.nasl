# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842847");
  script_cve_id("CVE-2016-0718", "CVE-2016-2830", "CVE-2016-2835", "CVE-2016-2836", "CVE-2016-2837", "CVE-2016-2838", "CVE-2016-2839", "CVE-2016-5250", "CVE-2016-5251", "CVE-2016-5252", "CVE-2016-5254", "CVE-2016-5255", "CVE-2016-5258", "CVE-2016-5259", "CVE-2016-5260", "CVE-2016-5261", "CVE-2016-5262", "CVE-2016-5263", "CVE-2016-5264", "CVE-2016-5265", "CVE-2016-5266", "CVE-2016-5268");
  script_tag(name:"creation_date", value:"2016-08-06 03:36:37 +0000 (Sat, 06 Aug 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-08-05 17:03:57 +0000 (Fri, 05 Aug 2016)");

  script_name("Ubuntu: Security Advisory (USN-3044-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS|16\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-3044-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3044-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-3044-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Gustavo Grieco discovered an out-of-bounds read during XML parsing in
some circumstances. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this to cause a
denial of service via application crash, or obtain sensitive information.
(CVE-2016-0718)

Toni Huttunen discovered that once a favicon is requested from a site,
the remote server can keep the network connection open even after the page
is closed. A remote attacked could potentially exploit this to track
users, resulting in information disclosure. (CVE-2016-2830)

Christian Holler, Tyson Smith, Boris Zbarsky, Byron Campen, Julian Seward,
Carsten Book, Gary Kwong, Jesse Ruderman, Andrew McCreight, and Phil
Ringnalda discovered multiple memory safety issues in Firefox. If a user
were tricked in to opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service via application
crash, or execute arbitrary code. (CVE-2016-2835, CVE-2016-2836)

A buffer overflow was discovered in the ClearKey Content Decryption
Module (CDM) during video playback. If a user were tricked in to opening
a specially crafted website, an attacker could potentially exploit this to
cause a denial of service via plugin process crash, or, in combination
with another vulnerability to escape the GMP sandbox, execute arbitrary
code. (CVE-2016-2837)

Atte Kettunen discovered a buffer overflow when rendering SVG content in
some circumstances. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this to cause a
denial of service via application crash, or execute arbitrary code.
(CVE-2016-2838)

Bert Massop discovered a crash in Cairo with version 0.10 of FFmpeg. If a
user were tricked in to opening a specially crafted website, an attacker
could potentially exploit this to execute arbitrary code. (CVE-2016-2839)

Catalin Dumitru discovered that URLs of resources loaded after a
navigation start could be leaked to the following page via the Resource
Timing API. An attacker could potentially exploit this to obtain sensitive
information. (CVE-2016-5250)

Firas Salem discovered an issue with non-ASCII and emoji characters in
data: URLs. An attacker could potentially exploit this to spoof the
addressbar contents. (CVE-2016-5251)

Georg Koppen discovered a stack buffer underflow during 2D graphics
rendering in some circumstances. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this to
cause a denial of service via application crash, or execute arbitrary
code. (CVE-2016-5252)

Abhishek Arya discovered a use-after-free when the alt key is used with
top-level menus. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial of
service via application crash, or execute arbitrary code. ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 16.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"48.0+build2-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"48.0+build2-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"48.0+build2-0ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS"))) {
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
