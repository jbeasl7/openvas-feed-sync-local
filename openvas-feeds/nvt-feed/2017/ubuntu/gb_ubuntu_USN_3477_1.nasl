# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843365");
  script_cve_id("CVE-2017-7826", "CVE-2017-7827", "CVE-2017-7828", "CVE-2017-7830", "CVE-2017-7831", "CVE-2017-7832", "CVE-2017-7833", "CVE-2017-7834", "CVE-2017-7835", "CVE-2017-7837", "CVE-2017-7838", "CVE-2017-7839", "CVE-2017-7840", "CVE-2017-7842");
  script_tag(name:"creation_date", value:"2017-11-18 06:32:50 +0000 (Sat, 18 Nov 2017)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-02 20:18:45 +0000 (Thu, 02 Aug 2018)");

  script_name("Ubuntu: Security Advisory (USN-3477-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|17\.04|17\.10)");

  script_xref(name:"Advisory-ID", value:"USN-3477-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3477-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-3477-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in Firefox. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service, read uninitialized
memory, obtain sensitive information, bypass same-origin restrictions,
bypass CSP protections, bypass mixed content blocking, spoof the
addressbar, or execute arbitrary code. (CVE-2017-7826, CVE-2017-7827,
CVE-2017-7828, CVE-2017-7830, CVE-2017-7831, CVE-2017-7832, CVE-2017-7833,
CVE-2017-7834, CVE-2017-7835, CVE-2017-7837, CVE-2017-7838, CVE-2017-7842)

It was discovered that javascript: URLs pasted in to the addressbar
would be executed instead of being blocked in some circumstances. If a
user were tricked in to copying a specially crafted URL in to the
addressbar, an attacker could potentially exploit this to conduct
cross-site scripting (XSS) attacks. (CVE-2017-7839)

It was discovered that exported bookmarks do not strip script elements
from user-supplied tags. If a user were tricked in to adding specially
crafted tags to bookmarks, exporting them and then opening the resulting
HTML file, an attacker could potentially exploit this to conduct
cross-site scripting (XSS) attacks. (CVE-2017-7840)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.04, Ubuntu 17.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"57.0+build4-0ubuntu0.14.04.4", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"57.0+build4-0ubuntu0.16.04.5", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU17.04") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"57.0+build4-0ubuntu0.17.04.5", rls:"UBUNTU17.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU17.10") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"57.0+build4-0ubuntu0.17.10.5", rls:"UBUNTU17.10"))) {
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
