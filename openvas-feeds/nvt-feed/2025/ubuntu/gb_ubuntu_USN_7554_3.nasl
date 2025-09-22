# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7554.3");
  script_cve_id("CVE-2021-47211", "CVE-2021-47353", "CVE-2023-52458", "CVE-2024-26966", "CVE-2024-42301", "CVE-2024-47701", "CVE-2024-53155", "CVE-2024-53168", "CVE-2024-56551", "CVE-2024-56596", "CVE-2024-57850");
  script_tag(name:"creation_date", value:"2025-06-05 04:08:39 +0000 (Thu, 05 Jun 2025)");
  script_version("2025-06-05T05:40:56+0000");
  script_tag(name:"last_modification", value:"2025-06-05 05:40:56 +0000 (Thu, 05 Jun 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-03 18:47:36 +0000 (Mon, 03 Mar 2025)");

  script_name("Ubuntu: Security Advisory (USN-7554-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7554-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7554-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-fips' package(s) announced via the USN-7554-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - Block layer subsystem,
 - Clock framework and drivers,
 - GPU drivers,
 - Parport drivers,
 - Ext4 file system,
 - JFFS2 file system,
 - JFS file system,
 - File systems infrastructure,
 - Sun RPC protocol,
 - USB sound devices,
(CVE-2024-42301, CVE-2024-26966, CVE-2023-52458, CVE-2024-47701,
CVE-2024-53155, CVE-2021-47211, CVE-2024-57850, CVE-2024-56551,
CVE-2021-47353, CVE-2024-56596, CVE-2024-53168)");

  script_tag(name:"affected", value:"'linux-fips' package(s) on Ubuntu 16.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1114-fips", ver:"4.4.0-1114.121", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-fips", ver:"4.4.0.1114.115", rls:"UBUNTU16.04 LTS"))) {
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
