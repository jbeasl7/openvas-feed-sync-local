# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843330");
  script_cve_id("CVE-2017-13720", "CVE-2017-13722");
  script_tag(name:"creation_date", value:"2017-10-11 07:57:28 +0000 (Wed, 11 Oct 2017)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-03 17:28:19 +0000 (Fri, 03 Nov 2017)");

  script_name("Ubuntu: Security Advisory (USN-3442-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|17\.04)");

  script_xref(name:"Advisory-ID", value:"USN-3442-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3442-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxfont, libxfont1, libxfont2' package(s) announced via the USN-3442-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libXfont incorrectly handled certain patterns in
PatternMatch. A local attacker could use this issue to cause libXfont to
crash, resulting in a denial of service, or possibly obtain sensitive
information. (CVE-2017-13720)

It was discovered that libXfont incorrectly handled certain malformed PCF
files. A local attacker could use this issue to cause libXfont to crash,
resulting in a denial of service, or possibly obtain sensitive information.
(CVE-2017-13722)");

  script_tag(name:"affected", value:"'libxfont, libxfont1, libxfont2' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libxfont1", ver:"1:1.4.7-1ubuntu0.3", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libxfont1", ver:"1:1.5.1-1ubuntu0.16.04.3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxfont2", ver:"1:2.0.1-3~ubuntu16.04.2", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libxfont1", ver:"1:1.5.2-4ubuntu0.1", rls:"UBUNTU17.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxfont2", ver:"1:2.0.1-3ubuntu0.1", rls:"UBUNTU17.04"))) {
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
