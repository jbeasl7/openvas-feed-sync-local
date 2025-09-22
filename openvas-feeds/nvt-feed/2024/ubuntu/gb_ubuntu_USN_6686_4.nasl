# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6686.4");
  script_cve_id("CVE-2023-22995", "CVE-2023-4134", "CVE-2023-46343", "CVE-2023-46862", "CVE-2023-51779", "CVE-2023-51782", "CVE-2023-6121", "CVE-2024-0340", "CVE-2024-0607");
  script_tag(name:"creation_date", value:"2024-03-21 04:09:31 +0000 (Thu, 21 Mar 2024)");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-08 18:17:05 +0000 (Wed, 08 Mar 2023)");

  script_name("Ubuntu: Security Advisory (USN-6686-4)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6686-4");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6686-4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-kvm' package(s) announced via the USN-6686-4 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the DesignWare USB3 for Qualcomm SoCs driver in the
Linux kernel did not properly handle certain error conditions during device
registration. A local attacker could possibly use this to cause a denial of
service (system crash). (CVE-2023-22995)

It was discovered that a race condition existed in the Cypress touchscreen
driver in the Linux kernel during device removal, leading to a use-after-
free vulnerability. A physically proximate attacker could use this to cause
a denial of service (system crash) or possibly execute arbitrary code.
(CVE-2023-4134)

Huang Si Cong discovered that the NFC Controller Interface (NCI) implementation in
the Linux kernel did not properly handle certain memory allocation failure
conditions, leading to a null pointer dereference vulnerability. A local
attacker could use this to cause a denial of service (system crash).
(CVE-2023-46343)

It was discovered that the io_uring subsystem in the Linux kernel contained
a race condition, leading to a null pointer dereference vulnerability. A
local attacker could use this to cause a denial of service (system crash).
(CVE-2023-46862)

It was discovered that a race condition existed in the Bluetooth subsystem
of the Linux kernel, leading to a use-after-free vulnerability. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2023-51779)

It was discovered that a race condition existed in the Rose X.25 protocol
implementation in the Linux kernel, leading to a use-after- free
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2023-51782)

Alon Zahavi discovered that the NVMe-oF/TCP subsystem of the Linux kernel
did not properly handle connect command payloads in certain situations,
leading to an out-of-bounds read vulnerability. A remote attacker could use
this to expose sensitive information (kernel memory). (CVE-2023-6121)

It was discovered that the VirtIO subsystem in the Linux kernel did not
properly initialize memory in some situations. A local attacker could use
this to possibly expose sensitive information (kernel memory).
(CVE-2024-0340)

Dan Carpenter discovered that the netfilter subsystem in the Linux kernel
did not store data in properly sized memory locations. A local user could
use this to cause a denial of service (system crash). (CVE-2024-0607)");

  script_tag(name:"affected", value:"'linux-kvm' package(s) on Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1052-kvm", ver:"5.15.0-1052.57", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"5.15.0.1052.48", rls:"UBUNTU22.04 LTS"))) {
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
