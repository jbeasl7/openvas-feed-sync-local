# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6922.2");
  script_cve_id("CVE-2024-24857", "CVE-2024-24858", "CVE-2024-24859", "CVE-2024-25739");
  script_tag(name:"creation_date", value:"2024-08-02 04:08:24 +0000 (Fri, 02 Aug 2024)");
  script_version("2024-08-02T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-08-02 05:05:39 +0000 (Fri, 02 Aug 2024)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:N/C:N/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-10 04:06:50 +0000 (Sat, 10 Feb 2024)");

  script_name("Ubuntu: Security Advisory (USN-6922-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6922-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6922-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lowlatency-hwe-6.5' package(s) announced via the USN-6922-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a race condition existed in the Bluetooth subsystem
in the Linux kernel when modifying certain settings values through debugfs.
A privileged local attacker could use this to cause a denial of service.
(CVE-2024-24857, CVE-2024-24858, CVE-2024-24859)

Chenyuan Yang discovered that the Unsorted Block Images (UBI) flash device
volume management subsystem did not properly validate logical eraseblock
sizes in certain situations. An attacker could possibly use this to cause a
denial of service (system crash). (CVE-2024-25739)");

  script_tag(name:"affected", value:"'linux-lowlatency-hwe-6.5' package(s) on Ubuntu 22.04.");

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

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-45-lowlatency", ver:"6.5.0-45.45.1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-45-lowlatency-64k", ver:"6.5.0-45.45.1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-64k-hwe-22.04", ver:"6.5.0.45.45.1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-hwe-22.04", ver:"6.5.0.45.45.1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
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
