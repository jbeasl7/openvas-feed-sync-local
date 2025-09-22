# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7247.1");
  script_cve_id("CVE-2019-14493", "CVE-2019-16249", "CVE-2019-19624", "CVE-2023-2617", "CVE-2023-2618");
  script_tag(name:"creation_date", value:"2025-02-04 04:07:50 +0000 (Tue, 04 Feb 2025)");
  script_version("2025-02-04T05:37:53+0000");
  script_tag(name:"last_modification", value:"2025-02-04 05:37:53 +0000 (Tue, 04 Feb 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-17 15:54:19 +0000 (Wed, 17 May 2023)");

  script_name("Ubuntu: Security Advisory (USN-7247-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7247-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7247-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opencv' package(s) announced via the USN-7247-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that OpenCV did not properly manage certain XML data,
leading to a NULL pointer dereference. If a user were tricked into
loading a specially crafted file, a remote attacker could possibly use
this issue to make OpenCV crash, resulting in a denial of service.
This issue only affected Ubuntu 18.04 LTS. (CVE-2019-14493)

It was discovered that OpenCV may perform out-of-bounds reads in certain
situations. An attacker could possibly use this issue to cause OpenCV to
crash, resulting in a denial of service, or the execution of arbitrary
code. This issue only affected Ubuntu 18.04 LTS.
(CVE-2019-16249, CVE-2019-19624)

It was discovered that the QR code module of OpenCV incorrectly processed
certain maliciously crafted QR codes. A remote attacker could possibly use
this issue to cause OpenCV to crash, resulting in a denial of service.
This issue only affected Ubuntu 22.04 LTS. (CVE-2023-2617, CVE-2023-2618)");

  script_tag(name:"affected", value:"'opencv' package(s) on Ubuntu 18.04, Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-core3.2", ver:"3.2.0+dfsg-4ubuntu0.1+esm4", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-dev", ver:"3.2.0+dfsg-4ubuntu0.1+esm4", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"opencv-data", ver:"3.2.0+dfsg-4ubuntu0.1+esm4", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-contrib4.5d", ver:"4.5.4+dfsg-9ubuntu4+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-core4.5d", ver:"4.5.4+dfsg-9ubuntu4+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-dev", ver:"4.5.4+dfsg-9ubuntu4+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-dnn4.5d", ver:"4.5.4+dfsg-9ubuntu4+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-flann4.5d", ver:"4.5.4+dfsg-9ubuntu4+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-imgcodecs4.5d", ver:"4.5.4+dfsg-9ubuntu4+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-objdetect4.5d", ver:"4.5.4+dfsg-9ubuntu4+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"opencv-data", ver:"4.5.4+dfsg-9ubuntu4+esm1", rls:"UBUNTU22.04 LTS"))) {
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
