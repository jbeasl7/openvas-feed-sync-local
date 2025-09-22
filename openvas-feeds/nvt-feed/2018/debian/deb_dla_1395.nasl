# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891395");
  script_cve_id("CVE-2017-14650", "CVE-2017-9774");
  script_tag(name:"creation_date", value:"2018-07-09 22:00:00 +0000 (Mon, 09 Jul 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-05 14:05:03 +0000 (Thu, 05 Oct 2017)");

  script_name("Debian: Security Advisory (DLA-1395-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-1395-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/DLA-1395-1");
  script_xref(name:"URL", value:"https://github.com/horde/Image/pull/1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'php-horde-image' package(s) announced via the DLA-1395-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there were two remote code execution vulnerabilities in php-horde-image, the image processing library for the Horde groupware tool:

CVE-2017-9774

A remote code execution vulnerability (RCE) that was exploitable by a logged-in user sending a maliciously crafted HTTP GET request to various image backends.

Note that the fix applied upstream has a regression in that it ignores the force aspect ratio option, see [link moved to references].

CVE-2017-14650

Another RCE that was exploitable by a logged-in user sending a maliciously crafted GET request specifically to the im image backend.

For Debian 8 Jessie, these issues have been fixed in php-horde-image version 2.1.0-4+deb8u1.

We recommend that you upgrade your php-horde-image packages.");

  script_tag(name:"affected", value:"'php-horde-image' package(s) on Debian 8.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"php-horde-image", ver:"2.1.0-4+deb8u1", rls:"DEB8"))) {
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
