# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845241");
  script_cve_id("CVE-2022-0511", "CVE-2022-22754", "CVE-2022-22755", "CVE-2022-22756", "CVE-2022-22757", "CVE-2022-22759", "CVE-2022-22760", "CVE-2022-22761", "CVE-2022-22764");
  script_tag(name:"creation_date", value:"2022-02-15 02:00:38 +0000 (Tue, 15 Feb 2022)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-29 22:51:42 +0000 (Thu, 29 Dec 2022)");

  script_name("Ubuntu: Security Advisory (USN-5284-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|21\.10)");

  script_xref(name:"Advisory-ID", value:"USN-5284-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5284-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-5284-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in Firefox. If a user were
tricked into opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service, bypass security
restrictions, obtain sensitive information, or execute arbitrary code.
(CVE-2022-0511, CVE-2022-22755, CVE-2022-22759, CVE-2022-22760,
CVE-2022-22761, CVE-2022-22764)

It was discovered that extensions of a particular type could auto-update
themselves and bypass the prompt that requests permissions. If a user
were tricked into installing a specially crafted extension, an attacker
could potentially exploit this to bypass security restrictions.
(CVE-2022-22754)

It was discovered that dragging and dropping an image into a folder could
result in it being marked as executable. If a user were tricked into
dragging and dropping a specially crafted image, an attacker could
potentially exploit this to execute arbitrary code. (CVE-2022-22756)

It was discovered that Remote Agent, used in WebDriver, did not validate
Host or Origin headers. If a user were tricked into opening a specially
crafted website with WebDriver enabled, an attacker could potentially
exploit this to connect back to the user's browser in order to control
it. (CVE-2022-22757)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 21.10.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"97.0+build2-0ubuntu0.18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"97.0+build2-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU21.10") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"97.0+build2-0ubuntu0.21.10.1", rls:"UBUNTU21.10"))) {
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
