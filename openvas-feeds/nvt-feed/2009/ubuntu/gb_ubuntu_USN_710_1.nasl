# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63305");
  script_cve_id("CVE-2008-3231", "CVE-2008-5233", "CVE-2008-5234", "CVE-2008-5236", "CVE-2008-5237", "CVE-2008-5238", "CVE-2008-5239", "CVE-2008-5240", "CVE-2008-5241", "CVE-2008-5242", "CVE-2008-5243", "CVE-2008-5244", "CVE-2008-5246", "CVE-2008-5248");
  script_tag(name:"creation_date", value:"2009-02-02 22:28:24 +0000 (Mon, 02 Feb 2009)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-710-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(6\.06\ LTS|7\.10|8\.04\ LTS|8\.10)");

  script_xref(name:"Advisory-ID", value:"USN-710-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-710-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xine-lib' package(s) announced via the USN-710-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that xine-lib did not correctly handle certain malformed
Ogg and Windows Media files. If a user or automated system were tricked into
opening a specially crafted Ogg or Windows Media file, an attacker could cause
xine-lib to crash, creating a denial of service. This issue only applied to
Ubuntu 6.06 LTS, 7.10, and 8.04 LTS. (CVE-2008-3231)

It was discovered that the MNG, MOD, and Real demuxers in xine-lib did not
correctly handle memory allocation failures. If a user or automated system were
tricked into opening a specially crafted MNG, MOD, or Real file, an attacker
could crash xine-lib or possibly execute arbitrary code with the privileges of
the user invoking the program. This issue only applied to Ubuntu 6.06 LTS, 7.10,
and 8.04 LTS. (CVE-2008-5233)

It was discovered that the QT demuxer in xine-lib did not correctly handle
an invalid metadata atom size, resulting in a heap-based buffer overflow. If a
user or automated system were tricked into opening a specially crafted MOV file,
an attacker could execute arbitrary code as the user invoking the program.
(CVE-2008-5234, CVE-2008-5242)

It was discovered that the Real, RealAudio, and Matroska demuxers in xine-lib
did not correctly handle malformed files, resulting in heap-based buffer
overflows. If a user or automated system were tricked into opening a specially
crafted Real, RealAudio, or Matroska file, an attacker could execute arbitrary
code as the user invoking the program. (CVE-2008-5236)

It was discovered that the MNG and QT demuxers in xine-lib did not correctly
handle malformed files, resulting in integer overflows. If a user or automated
system were tricked into opening a specially crafted MNG or MOV file, an
attacker could execute arbitrary code as the user invoking the program.
(CVE-2008-5237)

It was discovered that the Matroska, MOD, Real, and Real Audio demuxers in
xine-lib did not correctly handle malformed files, resulting in integer
overflows. If a user or automated system were tricked into opening a specially
crafted Matroska, MOD, Real, or Real Audio file, an attacker could execute
arbitrary code as the user invoking the program. This issue only applied to
Ubuntu 6.06 LTS, 7.10, and 8.04 LTS. (CVE-2008-5238)

It was discovered that the input handlers in xine-lib did not correctly handle
certain error codes, resulting in out-of-bounds reads and heap-based buffer
overflows. If a user or automated system were tricked into opening a specially
crafted file, stream, or URL, an attacker could execute arbitrary code as the
user invoking the program. (CVE-2008-5239)

It was discovered that the Matroska and Real demuxers in xine-lib did not
correctly handle memory allocation failures. If a user or automated system were
tricked into opening a specially crafted Matroska or Real file, an attacker
could crash xine-lib or possibly execute arbitrary code with the privileges of
the user invoking ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'xine-lib' package(s) on Ubuntu 6.06, Ubuntu 7.10, Ubuntu 8.04, Ubuntu 8.10.");

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

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libxine-main1", ver:"1.1.1+ubuntu2-7.10", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU7.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libxine1", ver:"1.1.7-1ubuntu1.4", rls:"UBUNTU7.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libxine1", ver:"1.1.11.1-1ubuntu3.2", rls:"UBUNTU8.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libxine1", ver:"1.1.15-0ubuntu3.1", rls:"UBUNTU8.10"))) {
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
