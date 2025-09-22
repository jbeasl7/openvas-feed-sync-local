# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841048");
  script_cve_id("CVE-2011-3929", "CVE-2011-3936", "CVE-2011-3940", "CVE-2011-3947", "CVE-2011-3951", "CVE-2011-3952", "CVE-2012-0851", "CVE-2012-0852", "CVE-2012-0853", "CVE-2012-0858", "CVE-2012-0859", "CVE-2012-0947");
  script_tag(name:"creation_date", value:"2012-06-19 04:12:08 +0000 (Tue, 19 Jun 2012)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-1479-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-1479-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1479-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg' package(s) announced via the USN-1479-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mateusz Jurczyk and Gynvael Coldwind discovered that FFmpeg incorrectly
handled certain malformed DV files. If a user were tricked into opening a
crafted DV file, an attacker could cause a denial of service via
application crash, or possibly execute arbitrary code with the privileges
of the user invoking the program. (CVE-2011-3929, CVE-2011-3936)

Mateusz Jurczyk and Gynvael Coldwind discovered that FFmpeg incorrectly
handled certain malformed NSV files. If a user were tricked into opening a
crafted NSV file, an attacker could cause a denial of service via
application crash, or possibly execute arbitrary code with the privileges
of the user invoking the program. (CVE-2011-3940)

Mateusz Jurczyk and Gynvael Coldwind discovered that FFmpeg incorrectly
handled certain malformed MJPEG-B files. If a user were tricked into
opening a crafted MJPEG-B file, an attacker could cause a denial of service
via application crash, or possibly execute arbitrary code with the
privileges of the user invoking the program. (CVE-2011-3947)

Mateusz Jurczyk and Gynvael Coldwind discovered that FFmpeg incorrectly
handled certain malformed DPCM files. If a user were tricked into opening a
crafted DPCM file, an attacker could cause a denial of service via
application crash, or possibly execute arbitrary code with the privileges
of the user invoking the program. (CVE-2011-3951)

Mateusz Jurczyk and Gynvael Coldwind discovered that FFmpeg incorrectly
handled certain malformed KMVC files. If a user were tricked into opening a
crafted KMVC file, an attacker could cause a denial of service via
application crash, or possibly execute arbitrary code with the privileges
of the user invoking the program. (CVE-2011-3952)

It was discovered that FFmpeg incorrectly handled certain malformed H.264
files. If a user were tricked into opening a crafted H.264 file, an
attacker could cause a denial of service via application crash, or possibly
execute arbitrary code with the privileges of the user invoking the
program. (CVE-2012-0851)

It was discovered that FFmpeg incorrectly handled certain malformed ADPCM
files. If a user were tricked into opening a crafted ADPCM file, an
attacker could cause a denial of service via application crash, or possibly
execute arbitrary code with the privileges of the user invoking the
program. (CVE-2012-0852)

It was discovered that FFmpeg incorrectly handled certain malformed Atrac 3
files. If a user were tricked into opening a crafted Atrac 3 file, an
attacker could cause a denial of service via application crash, or possibly
execute arbitrary code with the privileges of the user invoking the
program. (CVE-2012-0853)

It was discovered that FFmpeg incorrectly handled certain malformed Shorten
files. If a user were tricked into opening a crafted Shorten file, an
attacker could cause a denial of service via application crash, or possibly
execute arbitrary code with the privileges of ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ffmpeg' package(s) on Ubuntu 10.04.");

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

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec52", ver:"4:0.5.9-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavformat52", ver:"4:0.5.9-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS"))) {
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
