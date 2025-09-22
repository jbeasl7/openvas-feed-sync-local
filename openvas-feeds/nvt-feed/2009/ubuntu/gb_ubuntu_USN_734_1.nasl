# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63617");
  script_cve_id("CVE-2008-4610", "CVE-2008-4866", "CVE-2008-4867", "CVE-2009-0385");
  script_tag(name:"creation_date", value:"2009-03-19 23:52:38 +0000 (Thu, 19 Mar 2009)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-734-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(7\.10|8\.04\ LTS|8\.10)");

  script_xref(name:"Advisory-ID", value:"USN-734-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-734-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg, ffmpeg-debian' package(s) announced via the USN-734-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that FFmpeg did not correctly handle certain malformed
Ogg Media (OGM) files. If a user were tricked into opening a crafted Ogg
Media file, an attacker could cause the application using FFmpeg to crash,
leading to a denial of service. (CVE-2008-4610)

It was discovered that FFmpeg did not correctly handle certain parameters
when creating DTS streams. If a user were tricked into processing certain
commands, an attacker could cause a denial of service via application
crash, or possibly execute arbitrary code with the privileges of the user
invoking the program. This issue only affected Ubuntu 8.10. (CVE-2008-4866)

It was discovered that FFmpeg did not correctly handle certain malformed
DTS Coherent Acoustics (DCA) files. If a user were tricked into opening a
crafted DCA file, an attacker could cause a denial of service via
application crash, or possibly execute arbitrary code with the privileges
of the user invoking the program. (CVE-2008-4867)

It was discovered that FFmpeg did not correctly handle certain malformed 4X
movie (4xm) files. If a user were tricked into opening a crafted 4xm file,
an attacker could execute arbitrary code with the privileges of the user
invoking the program. (CVE-2009-0385)");

  script_tag(name:"affected", value:"'ffmpeg, ffmpeg-debian' package(s) on Ubuntu 7.10, Ubuntu 8.04, Ubuntu 8.10.");

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

if(release == "UBUNTU7.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec1d", ver:"3:0.cvs20070307-5ubuntu4.2", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavformat1d", ver:"3:0.cvs20070307-5ubuntu4.2", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU8.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec1d", ver:"3:0.cvs20070307-5ubuntu7.3", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavformat1d", ver:"3:0.cvs20070307-5ubuntu7.3", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU8.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec51", ver:"3:0.svn20080206-12ubuntu3.1", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavformat52", ver:"3:0.svn20080206-12ubuntu3.1", rls:"UBUNTU8.10"))) {
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
