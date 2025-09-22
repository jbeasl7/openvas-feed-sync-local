# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7506.2");
  script_cve_id("CVE-2021-46959", "CVE-2021-47150", "CVE-2021-47163", "CVE-2021-47191", "CVE-2021-47219", "CVE-2021-47245", "CVE-2021-47500", "CVE-2021-47506", "CVE-2021-47587", "CVE-2022-23041", "CVE-2023-52741", "CVE-2024-26689", "CVE-2024-26915", "CVE-2024-26974", "CVE-2024-26996", "CVE-2024-35864", "CVE-2024-36934", "CVE-2024-46771", "CVE-2024-46780", "CVE-2024-49944", "CVE-2024-50237", "CVE-2024-50256", "CVE-2024-53063", "CVE-2024-53066", "CVE-2024-53140", "CVE-2024-53173", "CVE-2024-56598", "CVE-2024-56631", "CVE-2024-56642", "CVE-2024-56650", "CVE-2024-56770", "CVE-2025-21971");
  script_tag(name:"creation_date", value:"2025-05-13 04:05:17 +0000 (Tue, 13 May 2025)");
  script_version("2025-05-13T05:41:39+0000");
  script_tag(name:"last_modification", value:"2025-05-13 05:41:39 +0000 (Tue, 13 May 2025)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-08 21:37:23 +0000 (Wed, 08 Jan 2025)");

  script_name("Ubuntu: Security Advisory (USN-7506-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7506-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7506-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-aws' package(s) announced via the USN-7506-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Demi Marie Obenour and Simon Gaiser discovered that several Xen para-
virtualization device frontends did not properly restrict the access rights
of device backends. An attacker could possibly use a malicious Xen backend
to gain access to memory pages of a guest VM or cause a denial of service
in the guest. (CVE-2022-23041)

Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - Hardware crypto device drivers,
 - GPU drivers,
 - IIO subsystem,
 - Media drivers,
 - Network drivers,
 - SCSI subsystem,
 - SPI subsystem,
 - USB Gadget drivers,
 - Ceph distributed file system,
 - File systems infrastructure,
 - JFS file system,
 - Network file system (NFS) client,
 - Network file system (NFS) server daemon,
 - NILFS2 file system,
 - SMB network file system,
 - CAN network layer,
 - IPv6 networking,
 - MAC80211 subsystem,
 - Netfilter,
 - Netlink,
 - Network traffic control,
 - SCTP protocol,
 - TIPC protocol,
(CVE-2024-56650, CVE-2024-26915, CVE-2024-50237, CVE-2024-53140,
CVE-2024-26996, CVE-2021-47506, CVE-2024-26974, CVE-2025-21971,
CVE-2024-56770, CVE-2024-53063, CVE-2021-47245, CVE-2024-36934,
CVE-2021-47500, CVE-2024-53173, CVE-2021-47219, CVE-2024-46771,
CVE-2024-56631, CVE-2024-46780, CVE-2024-35864, CVE-2021-46959,
CVE-2021-47191, CVE-2021-47587, CVE-2024-53066, CVE-2024-56642,
CVE-2021-47163, CVE-2024-50256, CVE-2021-47150, CVE-2024-56598,
CVE-2024-26689, CVE-2023-52741, CVE-2024-49944)");

  script_tag(name:"affected", value:"'linux-aws' package(s) on Ubuntu 14.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1143-aws", ver:"4.4.0-1143.149", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"4.4.0.1143.140", rls:"UBUNTU14.04 LTS"))) {
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
