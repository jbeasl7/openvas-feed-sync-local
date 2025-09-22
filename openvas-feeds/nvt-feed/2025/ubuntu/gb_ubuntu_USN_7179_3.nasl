# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7179.3");
  script_cve_id("CVE-2020-12351", "CVE-2020-12352", "CVE-2020-24490", "CVE-2024-26822", "CVE-2024-35963", "CVE-2024-35965", "CVE-2024-35966", "CVE-2024-35967", "CVE-2024-38553", "CVE-2024-40910", "CVE-2024-40973", "CVE-2024-43904", "CVE-2024-50264", "CVE-2024-53057");
  script_tag(name:"creation_date", value:"2025-01-08 04:08:41 +0000 (Wed, 08 Jan 2025)");
  script_version("2025-01-08T05:38:11+0000");
  script_tag(name:"last_modification", value:"2025-01-08 05:38:11 +0000 (Wed, 08 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-30 17:14:46 +0000 (Mon, 30 Nov 2020)");

  script_name("Ubuntu: Security Advisory (USN-7179-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7179-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7179-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-gke' package(s) announced via the USN-7179-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Andy Nguyen discovered that the Bluetooth L2CAP implementation in the Linux
kernel contained a type-confusion error. A physically proximate remote
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2020-12351)

Andy Nguyen discovered that the Bluetooth A2MP implementation in the Linux
kernel did not properly initialize memory in some situations. A physically
proximate remote attacker could use this to expose sensitive information
(kernel memory). (CVE-2020-12352)

Andy Nguyen discovered that the Bluetooth HCI event packet parser in the
Linux kernel did not properly handle event advertisements of certain sizes,
leading to a heap-based buffer overflow. A physically proximate remote
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2020-24490)

Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - GPU drivers,
 - Media drivers,
 - Network drivers,
 - SMB network file system,
 - Bluetooth subsystem,
 - Amateur Radio drivers,
 - Network traffic control,
 - VMware vSockets driver,
(CVE-2024-43904, CVE-2024-35963, CVE-2024-35967, CVE-2024-40973,
CVE-2024-26822, CVE-2024-35965, CVE-2024-40910, CVE-2024-38553,
CVE-2024-53057, CVE-2024-50264, CVE-2024-35966)");

  script_tag(name:"affected", value:"'linux-gke' package(s) on Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1072-gke", ver:"5.15.0-1072.78", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke", ver:"5.15.0.1072.71", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke-5.15", ver:"5.15.0.1072.71", rls:"UBUNTU22.04 LTS"))) {
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
