# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7173.3");
  script_cve_id("CVE-2021-47001", "CVE-2021-47101", "CVE-2022-38096", "CVE-2023-52821", "CVE-2024-35963", "CVE-2024-35965", "CVE-2024-35966", "CVE-2024-35967", "CVE-2024-36952", "CVE-2024-38553", "CVE-2024-38597", "CVE-2024-40910", "CVE-2024-43892", "CVE-2024-49967", "CVE-2024-50264", "CVE-2024-53057");
  script_tag(name:"creation_date", value:"2025-01-16 10:56:48 +0000 (Thu, 16 Jan 2025)");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-22 17:55:23 +0000 (Fri, 22 Nov 2024)");

  script_name("Ubuntu: Security Advisory (USN-7173-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7173-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7173-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-raspi-5.4' package(s) announced via the USN-7173-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ziming Zhang discovered that the DRM driver for VMware Virtual GPU did not
properly handle certain error conditions, leading to a NULL pointer
dereference. A local attacker could possibly trigger this vulnerability to
cause a denial of service. (CVE-2022-38096)

Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - GPU drivers,
 - Network drivers,
 - SCSI subsystem,
 - Ext4 file system,
 - Bluetooth subsystem,
 - Memory management,
 - Amateur Radio drivers,
 - Network traffic control,
 - Sun RPC protocol,
 - VMware vSockets driver,
(CVE-2023-52821, CVE-2024-40910, CVE-2024-43892, CVE-2024-49967,
CVE-2024-50264, CVE-2024-36952, CVE-2024-38553, CVE-2021-47101,
CVE-2021-47001, CVE-2024-35965, CVE-2024-35963, CVE-2024-35966,
CVE-2024-35967, CVE-2024-53057, CVE-2024-38597)");

  script_tag(name:"affected", value:"'linux-raspi-5.4' package(s) on Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1121-raspi", ver:"5.4.0-1121.133~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi-hwe-18.04", ver:"5.4.0.1121.133~18.04.1", rls:"UBUNTU18.04 LTS"))) {
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
