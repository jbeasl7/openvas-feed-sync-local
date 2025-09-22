# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840858");
  script_cve_id("CVE-2011-3504", "CVE-2011-4351", "CVE-2011-4352", "CVE-2011-4353", "CVE-2011-4364", "CVE-2011-4579");
  script_tag(name:"creation_date", value:"2012-01-09 08:00:07 +0000 (Mon, 09 Jan 2012)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1320-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|10\.10)");

  script_xref(name:"Advisory-ID", value:"USN-1320-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1320-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg' package(s) announced via the USN-1320-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Steve Manzuik discovered that FFmpeg incorrectly handled certain malformed
Matroska files. If a user were tricked into opening a crafted Matroska
file, an attacker could cause a denial of service via application crash, or
possibly execute arbitrary code with the privileges of the user invoking
the program. (CVE-2011-3504)

Phillip Langlois discovered that FFmpeg incorrectly handled certain
malformed QDM2 streams. If a user were tricked into opening a crafted QDM2
stream file, an attacker could cause a denial of service via application
crash, or possibly execute arbitrary code with the privileges of the user
invoking the program. (CVE-2011-4351)

Phillip Langlois discovered that FFmpeg incorrectly handled certain
malformed VP3 streams. If a user were tricked into opening a crafted file,
an attacker could cause a denial of service via application crash, or
possibly execute arbitrary code with the privileges of the user invoking
the program. This issue only affected Ubuntu 10.10. (CVE-2011-4352)

Phillip Langlois discovered that FFmpeg incorrectly handled certain
malformed VP5 and VP6 streams. If a user were tricked into opening a
crafted file, an attacker could cause a denial of service via application
crash, or possibly execute arbitrary code with the privileges of the user
invoking the program. (CVE-2011-4353)

It was discovered that FFmpeg incorrectly handled certain malformed VMD
files. If a user were tricked into opening a crafted VMD file, an attacker
could cause a denial of service via application crash, or possibly execute
arbitrary code with the privileges of the user invoking the program.
(CVE-2011-4364)

Phillip Langlois discovered that FFmpeg incorrectly handled certain
malformed SVQ1 streams. If a user were tricked into opening a crafted SVQ1
stream file, an attacker could cause a denial of service via application
crash, or possibly execute arbitrary code with the privileges of the user
invoking the program. (CVE-2011-4579)");

  script_tag(name:"affected", value:"'ffmpeg' package(s) on Ubuntu 10.04, Ubuntu 10.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec52", ver:"4:0.5.1-1ubuntu1.3", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavformat52", ver:"4:0.5.1-1ubuntu1.3", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU10.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec52", ver:"4:0.6-2ubuntu6.3", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavformat52", ver:"4:0.6-2ubuntu6.3", rls:"UBUNTU10.10"))) {
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
