# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843938");
  script_cve_id("CVE-2019-9788", "CVE-2019-9789", "CVE-2019-9790", "CVE-2019-9791", "CVE-2019-9792", "CVE-2019-9793", "CVE-2019-9795", "CVE-2019-9796", "CVE-2019-9797", "CVE-2019-9799", "CVE-2019-9802", "CVE-2019-9803", "CVE-2019-9805", "CVE-2019-9806", "CVE-2019-9807", "CVE-2019-9808", "CVE-2019-9809");
  script_tag(name:"creation_date", value:"2019-03-28 13:45:24 +0000 (Thu, 28 Mar 2019)");
  script_version("2025-08-15T05:40:49+0000");
  script_tag(name:"last_modification", value:"2025-08-15 05:40:49 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-08 23:43:00 +0000 (Thu, 08 Feb 2024)");

  script_name("Ubuntu: Security Advisory (USN-3918-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|18\.10)");

  script_xref(name:"Advisory-ID", value:"USN-3918-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3918-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-3918-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in Firefox. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service via application
crash, denial of service via successive FTP authorization prompts or modal
alerts, trick the user with confusing permission request prompts, obtain
sensitive information, conduct social engineering attacks, or execute
arbitrary code. (CVE-2019-9788, CVE-2019-9789, CVE-2019-9790,
CVE-2019-9791, CVE-2019-9792, CVE-2019-9795, CVE-2019-9796, CVE-2019-9797,
CVE-2019-9799, CVE-2019-9802, CVE-2019-9805, CVE-2019-9806, CVE-2019-9807,
CVE-2019-9808, CVE-2019-9809)

A mechanism was discovered that removes some bounds checking for string,
array, or typed array accesses if Spectre mitigations have been disabled.
If a user were tricked in to opening a specially crafted website with
Spectre mitigations disabled, an attacker could potentially exploit this
to cause a denial of service, or execute arbitrary code. (CVE-2019-9793)

It was discovered that Upgrade-Insecure-Requests was incorrectly enforced
for same-origin navigation. An attacker could potentially exploit this to
conduct machine-in-the-middle (MITM) attacks. (CVE-2019-9803)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 18.10.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"66.0+build3-0ubuntu0.16.04.2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"66.0+build3-0ubuntu0.18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.10") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"66.0+build3-0ubuntu0.18.10.1", rls:"UBUNTU18.10"))) {
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
