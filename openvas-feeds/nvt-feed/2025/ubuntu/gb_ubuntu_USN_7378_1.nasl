# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7378.1");
  script_cve_id("CVE-2025-27830", "CVE-2025-27831", "CVE-2025-27832", "CVE-2025-27833", "CVE-2025-27834", "CVE-2025-27835", "CVE-2025-27836");
  script_tag(name:"creation_date", value:"2025-03-28 04:04:17 +0000 (Fri, 28 Mar 2025)");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-7378-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|24\.04\ LTS|24\.10)");

  script_xref(name:"Advisory-ID", value:"USN-7378-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7378-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ghostscript' package(s) announced via the USN-7378-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Ghostscript incorrectly serialized DollarBlend in
certain fonts. An attacker could use this issue to cause Ghostscript to
crash, resulting in a denial of service, or possibly execute arbitrary
code. (CVE-2025-27830)

It was discovered that Ghostscript incorrectly handled the DOCXWRITE
TXTWRITE device. An attacker could use this issue to cause Ghostscript to
crash, resulting in a denial of service, or possibly execute arbitrary
code. This issue only affected Ubuntu 22.04 LTS, Ubuntu 24.04 LTS, and
Ubuntu 24.10. (CVE-2025-27831)

It was discovered that Ghostscript incorrectly handled the NPDL device. An
attacker could use this issue to cause Ghostscript to crash, resulting in a
denial of service, or possibly execute arbitrary code. (CVE-2025-27832)

It was discovered that Ghostscript incorrectly handled certain long TTF
file names. An attacker could use this issue to cause Ghostscript to
crash, resulting in a denial of service, or possibly execute arbitrary
code. This issue only affected Ubuntu 24.04 LTS and Ubuntu 24.10.
(CVE-2025-27833)

It was discovered that Ghostscript incorrectly handled oversized Type 4
functions in certain PDF documents. An attacker could use this issue to
cause Ghostscript to crash, resulting in a denial of service, or possibly
execute arbitrary code. This issue only affected Ubuntu 22.04 LTS, Ubuntu
24.04 LTS, and Ubuntu 24.10. (CVE-2025-27834)

It was discovered that Ghostscript incorrectly handled converting certain
glyphs to Unicode. An attacker could use this issue to cause Ghostscript to
crash, resulting in a denial of service, or possibly execute arbitrary
code. (CVE-2025-27835)

It was discovered that Ghostscript incorrectly handled the BJ10V device. An
attacker could use this issue to cause Ghostscript to crash, resulting in a
denial of service, or possibly execute arbitrary code. (CVE-2025-27836)");

  script_tag(name:"affected", value:"'ghostscript' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04, Ubuntu 24.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ghostscript", ver:"9.50~dfsg-5ubuntu4.15", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgs9", ver:"9.50~dfsg-5ubuntu4.15", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"ghostscript", ver:"9.55.0~dfsg1-0ubuntu5.11", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgs9", ver:"9.55.0~dfsg1-0ubuntu5.11", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"ghostscript", ver:"10.02.1~dfsg1-0ubuntu7.5", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgs10", ver:"10.02.1~dfsg1-0ubuntu7.5", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU24.10") {

  if(!isnull(res = isdpkgvuln(pkg:"ghostscript", ver:"10.03.1~dfsg1-0ubuntu2.2", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgs10", ver:"10.03.1~dfsg1-0ubuntu2.2", rls:"UBUNTU24.10"))) {
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
