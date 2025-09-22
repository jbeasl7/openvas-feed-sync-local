# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7448.1");
  script_cve_id("CVE-2024-57948", "CVE-2024-57949", "CVE-2024-57950", "CVE-2024-57951", "CVE-2024-57952", "CVE-2025-21665", "CVE-2025-21666", "CVE-2025-21667", "CVE-2025-21668", "CVE-2025-21669", "CVE-2025-21670", "CVE-2025-21672", "CVE-2025-21673", "CVE-2025-21674", "CVE-2025-21675", "CVE-2025-21676", "CVE-2025-21677", "CVE-2025-21678", "CVE-2025-21680", "CVE-2025-21681", "CVE-2025-21682", "CVE-2025-21683", "CVE-2025-21684", "CVE-2025-21685", "CVE-2025-21689", "CVE-2025-21690", "CVE-2025-21691", "CVE-2025-21692", "CVE-2025-21693", "CVE-2025-21694", "CVE-2025-21695", "CVE-2025-21696", "CVE-2025-21697", "CVE-2025-21699", "CVE-2025-21700", "CVE-2025-21701", "CVE-2025-21702", "CVE-2025-21703", "CVE-2025-21756", "CVE-2025-21993", "CVE-2025-2312");
  script_tag(name:"creation_date", value:"2025-04-24 04:04:27 +0000 (Thu, 24 Apr 2025)");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-21 15:59:44 +0000 (Fri, 21 Feb 2025)");

  script_name("Ubuntu: Security Advisory (USN-7448-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(24\.04\ LTS|24\.10)");

  script_xref(name:"Advisory-ID", value:"USN-7448-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7448-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure, linux-azure-6.11' package(s) announced via the USN-7448-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the CIFS network file system implementation in the
Linux kernel did not properly verify the target namespace when handling
upcalls. An attacker could use this to expose sensitive information.
(CVE-2025-2312)

Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - GPIO subsystem,
 - GPU drivers,
 - IRQ chip drivers,
 - Network drivers,
 - Mellanox network drivers,
 - x86 platform drivers,
 - i.MX PM domains,
 - SCSI subsystem,
 - USB Serial drivers,
 - AFS file system,
 - GFS2 file system,
 - File systems infrastructure,
 - Proc file system,
 - SMB network file system,
 - Timer subsystem,
 - Kernel CPU control infrastructure,
 - Memory management,
 - Networking core,
 - Ethtool driver,
 - IEEE 802.15.4 subsystem,
 - Open vSwitch,
 - Network traffic control,
 - VMware vSockets driver,
(CVE-2025-21694, CVE-2025-21993, CVE-2025-21684, CVE-2025-21681,
CVE-2025-21675, CVE-2025-21672, CVE-2025-21696, CVE-2025-21691,
CVE-2025-21683, CVE-2025-21666, CVE-2025-21682, CVE-2025-21697,
CVE-2025-21668, CVE-2025-21701, CVE-2025-21670, CVE-2025-21676,
CVE-2025-21695, CVE-2025-21692, CVE-2025-21674, CVE-2025-21699,
CVE-2024-57948, CVE-2025-21677, CVE-2024-57951, CVE-2025-21702,
CVE-2025-21700, CVE-2024-57949, CVE-2025-21669, CVE-2025-21703,
CVE-2025-21756, CVE-2025-21667, CVE-2024-57952, CVE-2024-57950,
CVE-2025-21685, CVE-2025-21693, CVE-2025-21678, CVE-2025-21665,
CVE-2025-21680, CVE-2025-21689, CVE-2025-21690, CVE-2025-21673)");

  script_tag(name:"affected", value:"'linux-azure, linux-azure-6.11' package(s) on Ubuntu 24.04, Ubuntu 24.10.");

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

if(release == "UBUNTU24.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.11.0-1013-azure", ver:"6.11.0-1013.13~24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.11.0-1013-azure-fde", ver:"6.11.0-1013.13~24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"6.11.0-1013.13~24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-fde", ver:"6.11.0-1013.13~24.04.1", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.11.0-1013-azure", ver:"6.11.0-1013.13", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.11.0-1013-azure-fde", ver:"6.11.0-1013.13", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"6.11.0-1013.13", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-fde", ver:"6.11.0-1013.13", rls:"UBUNTU24.10"))) {
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
