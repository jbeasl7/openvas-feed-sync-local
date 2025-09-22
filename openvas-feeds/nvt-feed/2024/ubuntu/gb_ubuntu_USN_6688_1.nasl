# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6688.1");
  script_cve_id("CVE-2023-46838", "CVE-2023-50431", "CVE-2023-52436", "CVE-2023-52438", "CVE-2023-52439", "CVE-2023-52443", "CVE-2023-52444", "CVE-2023-52445", "CVE-2023-52447", "CVE-2023-52448", "CVE-2023-52449", "CVE-2023-52451", "CVE-2023-52454", "CVE-2023-52456", "CVE-2023-52457", "CVE-2023-52458", "CVE-2023-52462", "CVE-2023-52463", "CVE-2023-52464", "CVE-2023-52467", "CVE-2023-52469", "CVE-2023-52470", "CVE-2023-52583", "CVE-2023-52584", "CVE-2023-52587", "CVE-2023-52588", "CVE-2023-52589", "CVE-2023-52593", "CVE-2023-52594", "CVE-2023-52595", "CVE-2023-52597", "CVE-2023-52598", "CVE-2023-52599", "CVE-2023-52600", "CVE-2023-52601", "CVE-2023-52602", "CVE-2023-52603", "CVE-2023-52604", "CVE-2023-52605", "CVE-2023-52606", "CVE-2023-52607", "CVE-2023-5633", "CVE-2023-6610", "CVE-2024-0340", "CVE-2024-1085", "CVE-2024-1086", "CVE-2024-23849", "CVE-2024-24860", "CVE-2024-26581", "CVE-2024-26588", "CVE-2024-26589", "CVE-2024-26591", "CVE-2024-26592", "CVE-2024-26594", "CVE-2024-26597", "CVE-2024-26598", "CVE-2024-26599", "CVE-2024-26600", "CVE-2024-26601", "CVE-2024-26624", "CVE-2024-26625", "CVE-2024-26627", "CVE-2024-26628");
  script_tag(name:"creation_date", value:"2024-03-12 04:09:07 +0000 (Tue, 12 Mar 2024)");
  script_version("2025-01-09T06:16:22+0000");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-07 20:17:40 +0000 (Tue, 07 Jan 2025)");

  script_name("Ubuntu: Security Advisory (USN-6688-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6688-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6688-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-oem-6.1' package(s) announced via the USN-6688-1 advisory.");

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

Murray McAllister discovered that the VMware Virtual GPU DRM driver in the
Linux kernel did not properly handle memory objects when storing surfaces,
leading to a use-after-free vulnerability. A local attacker in a guest VM
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2023-5633)

It was discovered that the CIFS network file system implementation in the
Linux kernel did not properly validate certain SMB messages, leading to an
out-of-bounds read vulnerability. An attacker could use this to cause a
denial of service (system crash) or possibly expose sensitive information.
(CVE-2023-6610)

It was discovered that the VirtIO subsystem in the Linux kernel did not
properly initialize memory in some situations. A local attacker could use
this to possibly expose sensitive information (kernel memory).
(CVE-2024-0340)

Lonial Con discovered that the netfilter subsystem in the Linux kernel did
not properly handle element deactivation in certain cases, leading to a
use-after-free vulnerability. A local attacker could use this to cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2024-1085)

Notselwyn discovered that the netfilter subsystem in the Linux kernel did
not properly handle verdict parameters in certain cases, leading to a use-
after-free vulnerability. A local attacker could use this to cause a denial
of service (system crash) or possibly execute arbitrary code.
(CVE-2024-1086)

Chenyuan Yang discovered that the RDS Protocol implementation in the Linux
kernel contained an out-of-bounds read vulnerability. An attacker could use
this to possibly cause a denial of service (system crash). (CVE-2024-23849)

It was discovered that a race condition existed in the Bluetooth subsystem
in the Linux kernel, leading to a null pointer dereference vulnerability. A
privileged local attacker could use this to possibly cause a denial of
service (system crash). (CVE-2024-24860)

Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - Architecture specifics,
 - Block layer,
 - ACPI drivers,
 - Android drivers,
 - EDAC drivers,
 - GPU drivers,
 - InfiniBand drivers,
 - Media drivers,
 - Multifunction device drivers,
 - ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-oem-6.1' package(s) on Ubuntu 22.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-1035-oem", ver:"6.1.0-1035.35", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-22.04", ver:"6.1.0.1035.36", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-22.04a", ver:"6.1.0.1035.36", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-22.04b", ver:"6.1.0.1035.36", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-22.04c", ver:"6.1.0.1035.36", rls:"UBUNTU22.04 LTS"))) {
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
