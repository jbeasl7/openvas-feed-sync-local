# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7496.5");
  script_cve_id("CVE-2021-47150", "CVE-2021-47163", "CVE-2021-47191", "CVE-2021-47219", "CVE-2023-52458", "CVE-2023-52664", "CVE-2023-52741", "CVE-2023-52927", "CVE-2024-26689", "CVE-2024-26915", "CVE-2024-26974", "CVE-2024-26996", "CVE-2024-35864", "CVE-2024-36015", "CVE-2024-36934", "CVE-2024-46771", "CVE-2024-46780", "CVE-2024-49925", "CVE-2024-49944", "CVE-2024-50237", "CVE-2024-50256", "CVE-2024-50296", "CVE-2024-53063", "CVE-2024-53066", "CVE-2024-53140", "CVE-2024-53173", "CVE-2024-56598", "CVE-2024-56631", "CVE-2024-56642", "CVE-2024-56650", "CVE-2024-56651", "CVE-2024-56770", "CVE-2025-21971");
  script_tag(name:"creation_date", value:"2025-05-08 04:05:12 +0000 (Thu, 08 May 2025)");
  script_version("2025-05-08T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-05-08 05:40:19 +0000 (Thu, 08 May 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-06 19:33:57 +0000 (Mon, 06 Jan 2025)");

  script_name("Ubuntu: Security Advisory (USN-7496-5)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7496-5");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7496-5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure-fips' package(s) announced via the USN-7496-5 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - Block layer subsystem,
 - Character device driver,
 - Hardware crypto device drivers,
 - GPU drivers,
 - Media drivers,
 - Network drivers,
 - SCSI subsystem,
 - USB Gadget drivers,
 - Framebuffer layer,
 - Ceph distributed file system,
 - File systems infrastructure,
 - JFS file system,
 - Network file system (NFS) client,
 - NILFS2 file system,
 - SMB network file system,
 - Netfilter,
 - CAN network layer,
 - IPv6 networking,
 - MAC80211 subsystem,
 - Netlink,
 - Network traffic control,
 - SCTP protocol,
 - TIPC protocol,
(CVE-2024-49944, CVE-2024-26996, CVE-2024-46771, CVE-2024-56651,
CVE-2023-52927, CVE-2021-47191, CVE-2024-56642, CVE-2023-52664,
CVE-2024-53173, CVE-2021-47150, CVE-2024-56770, CVE-2024-50237,
CVE-2024-46780, CVE-2024-36015, CVE-2023-52458, CVE-2024-49925,
CVE-2024-53063, CVE-2024-53066, CVE-2025-21971, CVE-2024-50296,
CVE-2024-50256, CVE-2024-35864, CVE-2024-56631, CVE-2024-53140,
CVE-2021-47219, CVE-2024-56598, CVE-2024-36934, CVE-2021-47163,
CVE-2024-26915, CVE-2024-56650, CVE-2024-26974, CVE-2023-52741,
CVE-2024-26689)");

  script_tag(name:"affected", value:"'linux-azure-fips' package(s) on Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-2097-azure-fips", ver:"4.15.0-2097.103", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-fips", ver:"4.15.0.2097.93", rls:"UBUNTU18.04 LTS"))) {
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
