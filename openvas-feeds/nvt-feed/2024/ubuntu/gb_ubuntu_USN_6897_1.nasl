# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6897.1");
  script_cve_id("CVE-2024-29506", "CVE-2024-29507", "CVE-2024-29508", "CVE-2024-29509", "CVE-2024-29511");
  script_tag(name:"creation_date", value:"2024-07-16 04:08:55 +0000 (Tue, 16 Jul 2024)");
  script_version("2024-08-05T05:05:50+0000");
  script_tag(name:"last_modification", value:"2024-08-05 05:05:50 +0000 (Mon, 05 Aug 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-02 20:10:32 +0000 (Fri, 02 Aug 2024)");

  script_name("Ubuntu: Security Advisory (USN-6897-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|24\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6897-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6897-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ghostscript' package(s) announced via the USN-6897-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Ghostscript incorrectly handled certain long PDF
filter names. An attacker could possibly use this issue to cause
Ghostscript to crash, resulting in a denial of service. This issue only
affected Ubuntu 22.04 LTS and Ubuntu 24.04 LTS. (CVE-2024-29506)

It was discovered that Ghostscript incorrectly handled certain API
parameters. An attacker could possibly use this issue to cause Ghostscript
to crash, resulting in a denial of service. This issue only affected Ubuntu
24.04 LTS. (CVE-2024-29507)

It was discovered that Ghostscript incorrectly handled certain BaseFont
names. An attacker could use this issue to cause Ghostscript to crash,
resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2024-29508)

It was discovered that Ghostscript incorrectly handled certain PDF
passwords that contained NULL bytes. An attacker could use this issue to
cause Ghostscript to crash, resulting in a denial of service, or possibly
execute arbitrary code. This issue only affected Ubuntu 22.04 LTS and
Ubuntu 24.04 LTS. (CVE-2024-29509)

It was discovered that Ghostscript incorrectly handled certain certain file
paths when doing OCR. An attacker could use this issue to read arbitrary
files and write error messages to arbitrary files. This issue only affected
Ubuntu 22.04 LTS and Ubuntu 24.04 LTS. (CVE-2024-29511)");

  script_tag(name:"affected", value:"'ghostscript' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"ghostscript", ver:"9.50~dfsg-5ubuntu4.13", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgs9", ver:"9.50~dfsg-5ubuntu4.13", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"ghostscript", ver:"9.55.0~dfsg1-0ubuntu5.9", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgs9", ver:"9.55.0~dfsg1-0ubuntu5.9", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU24.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"ghostscript", ver:"10.02.1~dfsg1-0ubuntu7.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgs10", ver:"10.02.1~dfsg1-0ubuntu7.3", rls:"UBUNTU24.04 LTS"))) {
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
