# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6777.2");
  script_cve_id("CVE-2021-46981", "CVE-2023-47233", "CVE-2023-52439", "CVE-2023-52524", "CVE-2023-52530", "CVE-2023-52566", "CVE-2023-52583", "CVE-2023-52601", "CVE-2023-52602", "CVE-2023-52604", "CVE-2024-26614", "CVE-2024-26622", "CVE-2024-26635", "CVE-2024-26704", "CVE-2024-26735", "CVE-2024-26801", "CVE-2024-26805");
  script_tag(name:"creation_date", value:"2024-05-21 04:07:33 +0000 (Tue, 21 May 2024)");
  script_version("2025-01-15T05:38:11+0000");
  script_tag(name:"last_modification", value:"2025-01-15 05:38:11 +0000 (Wed, 15 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-14 15:37:59 +0000 (Tue, 14 Jan 2025)");

  script_name("Ubuntu: Security Advisory (USN-6777-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6777-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6777-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure' package(s) announced via the USN-6777-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Zheng Wang discovered that the Broadcom FullMAC WLAN driver in the Linux
kernel contained a race condition during device removal, leading to a use-
after-free vulnerability. A physically proximate attacker could possibly
use this to cause a denial of service (system crash). (CVE-2023-47233)

Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - Block layer subsystem,
 - Userspace I/O drivers,
 - Ceph distributed file system,
 - Ext4 file system,
 - JFS file system,
 - NILFS2 file system,
 - Bluetooth subsystem,
 - Networking core,
 - IPv4 networking,
 - IPv6 networking,
 - Logical Link layer,
 - MAC80211 subsystem,
 - Netlink,
 - NFC subsystem,
 - Tomoyo security module,
(CVE-2023-52524, CVE-2023-52530, CVE-2023-52601, CVE-2023-52439,
CVE-2024-26635, CVE-2023-52602, CVE-2024-26614, CVE-2024-26704,
CVE-2023-52604, CVE-2023-52566, CVE-2021-46981, CVE-2024-26622,
CVE-2024-26735, CVE-2024-26805, CVE-2024-26801, CVE-2023-52583)");

  script_tag(name:"affected", value:"'linux-azure' package(s) on Ubuntu 14.04, Ubuntu 16.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1177-azure", ver:"4.15.0-1177.192~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"4.15.0.1177.192~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1177-azure", ver:"4.15.0-1177.192~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"4.15.0.1177.192~16.04.1", rls:"UBUNTU16.04 LTS"))) {
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
