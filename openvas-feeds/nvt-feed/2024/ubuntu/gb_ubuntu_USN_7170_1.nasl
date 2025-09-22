# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.7170.1");
  script_cve_id("CVE-2024-47704", "CVE-2024-49893", "CVE-2024-49896", "CVE-2024-49897", "CVE-2024-49898", "CVE-2024-49899", "CVE-2024-49904", "CVE-2024-49905", "CVE-2024-49906", "CVE-2024-49907", "CVE-2024-49908", "CVE-2024-49909", "CVE-2024-49910", "CVE-2024-49911", "CVE-2024-49912", "CVE-2024-49913", "CVE-2024-49914", "CVE-2024-49915", "CVE-2024-49916", "CVE-2024-49917", "CVE-2024-49918", "CVE-2024-49919", "CVE-2024-49920", "CVE-2024-49921", "CVE-2024-49922", "CVE-2024-49923", "CVE-2024-49967", "CVE-2024-50264", "CVE-2024-53057");
  script_tag(name:"creation_date", value:"2024-12-18 04:08:13 +0000 (Wed, 18 Dec 2024)");
  script_version("2025-01-09T06:16:22+0000");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-22 17:55:23 +0000 (Fri, 22 Nov 2024)");

  script_name("Ubuntu: Security Advisory (USN-7170-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU24\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7170-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7170-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-oem-6.11' package(s) announced via the USN-7170-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - GPU drivers,
 - Ext4 file system,
 - Network traffic control,
 - VMware vSockets driver,
(CVE-2024-49914, CVE-2024-49912, CVE-2024-49919, CVE-2024-49905,
CVE-2024-49909, CVE-2024-47704, CVE-2024-49916, CVE-2024-49908,
CVE-2024-49899, CVE-2024-49923, CVE-2024-49921, CVE-2024-50264,
CVE-2024-49911, CVE-2024-49893, CVE-2024-53057, CVE-2024-49904,
CVE-2024-49898, CVE-2024-49907, CVE-2024-49897, CVE-2024-49913,
CVE-2024-49967, CVE-2024-49922, CVE-2024-49920, CVE-2024-49896,
CVE-2024-49906, CVE-2024-49917, CVE-2024-49910, CVE-2024-49915,
CVE-2024-49918)");

  script_tag(name:"affected", value:"'linux-oem-6.11' package(s) on Ubuntu 24.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.11.0-1010-oem", ver:"6.11.0-1010.10", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-24.04b", ver:"6.11.0-1010.10", rls:"UBUNTU24.04 LTS"))) {
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
