# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6653.4");
  script_cve_id("CVE-2023-51780", "CVE-2023-51781", "CVE-2023-6915", "CVE-2024-0565", "CVE-2024-0646");
  script_tag(name:"creation_date", value:"2024-03-05 04:08:40 +0000 (Tue, 05 Mar 2024)");
  script_version("2024-03-05T05:05:54+0000");
  script_tag(name:"last_modification", value:"2024-03-05 05:05:54 +0000 (Tue, 05 Mar 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-24 21:04:26 +0000 (Wed, 24 Jan 2024)");

  script_name("Ubuntu: Security Advisory (USN-6653-4)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6653-4");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6653-4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-gke' package(s) announced via the USN-6653-4 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a race condition existed in the ATM (Asynchronous
Transfer Mode) subsystem of the Linux kernel, leading to a use-after-free
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2023-51780)

It was discovered that a race condition existed in the AppleTalk networking
subsystem of the Linux kernel, leading to a use-after-free vulnerability. A
local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2023-51781)

Zhenghan Wang discovered that the generic ID allocator implementation in
the Linux kernel did not properly check for null bitmap when releasing IDs.
A local attacker could use this to cause a denial of service (system
crash). (CVE-2023-6915)

Robert Morris discovered that the CIFS network file system implementation
in the Linux kernel did not properly validate certain server commands
fields, leading to an out-of-bounds read vulnerability. An attacker could
use this to cause a denial of service (system crash) or possibly expose
sensitive information. (CVE-2024-0565)

Jann Horn discovered that the TLS subsystem in the Linux kernel did not
properly handle spliced messages, leading to an out-of-bounds write
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2024-0646)");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1051-gke", ver:"5.15.0-1051.56", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke", ver:"5.15.0.1051.50", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke-5.15", ver:"5.15.0.1051.50", rls:"UBUNTU22.04 LTS"))) {
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
