# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6724.2");
  script_cve_id("CVE-2023-46838", "CVE-2023-50431", "CVE-2023-52429", "CVE-2023-52434", "CVE-2023-52435", "CVE-2023-52436", "CVE-2023-52438", "CVE-2023-52439", "CVE-2023-6610", "CVE-2024-22705", "CVE-2024-23850", "CVE-2024-23851");
  script_tag(name:"creation_date", value:"2024-04-17 04:10:18 +0000 (Wed, 17 Apr 2024)");
  script_version("2024-04-18T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-04-18 05:05:33 +0000 (Thu, 18 Apr 2024)");
  script_tag(name:"cvss_base", value:"7.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-03-15 14:21:29 +0000 (Fri, 15 Mar 2024)");

  script_name("Ubuntu: Security Advisory (USN-6724-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|23\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6724-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6724-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-aws-6.5, linux-raspi' package(s) announced via the USN-6724-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Pratyush Yadav discovered that the Xen network backend implementation in
the Linux kernel did not properly handle zero length data request, leading
to a null pointer dereference vulnerability. An attacker in a guest VM
could possibly use this to cause a denial of service (host domain crash).
(CVE-2023-46838)

It was discovered that the Habana's AI Processors driver in the Linux
kernel did not properly initialize certain data structures before passing
them to user space. A local attacker could use this to expose sensitive
information (kernel memory). (CVE-2023-50431)

It was discovered that the device mapper driver in the Linux kernel did not
properly validate target size during certain memory allocations. A local
attacker could use this to cause a denial of service (system crash).
(CVE-2023-52429, CVE-2024-23851)

It was discovered that the CIFS network file system implementation in the
Linux kernel did not properly validate certain SMB messages, leading to an
out-of-bounds read vulnerability. An attacker could use this to cause a
denial of service (system crash) or possibly expose sensitive information.
(CVE-2023-6610)

Yang Chaoming discovered that the KSMBD implementation in the Linux kernel
did not properly validate request buffer sizes, leading to an out-of-bounds
read vulnerability. An attacker could use this to cause a denial of service
(system crash) or possibly expose sensitive information. (CVE-2024-22705)

Chenyuan Yang discovered that the btrfs file system in the Linux kernel did
not properly handle read operations on newly created subvolumes in certain
conditions. A local attacker could use this to cause a denial of service
(system crash). (CVE-2024-23850)

Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - Android drivers,
 - Userspace I/O drivers,
 - F2FS file system,
 - SMB network file system,
 - Networking core,
(CVE-2023-52434, CVE-2023-52436, CVE-2023-52435, CVE-2023-52439,
CVE-2023-52438)");

  script_tag(name:"affected", value:"'linux-aws-6.5, linux-raspi' package(s) on Ubuntu 22.04, Ubuntu 23.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-1017-aws", ver:"6.5.0-1017.17~22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"6.5.0.1017.17~22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU23.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-1014-raspi", ver:"6.5.0-1014.17", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi", ver:"6.5.0.1014.15", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi-nolpae", ver:"6.5.0.1014.15", rls:"UBUNTU23.10"))) {
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
