# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843376");
  script_cve_id("CVE-2017-1000255", "CVE-2017-12153", "CVE-2017-12154", "CVE-2017-12188", "CVE-2017-12190", "CVE-2017-12192", "CVE-2017-14156", "CVE-2017-14489", "CVE-2017-14954", "CVE-2017-15265", "CVE-2017-15537", "CVE-2017-15649", "CVE-2017-16525", "CVE-2017-16526", "CVE-2017-16527", "CVE-2017-16529", "CVE-2017-16530", "CVE-2017-16531", "CVE-2017-16533", "CVE-2017-16534");
  script_tag(name:"creation_date", value:"2017-11-22 06:32:50 +0000 (Wed, 22 Nov 2017)");
  script_version("2025-08-15T05:40:49+0000");
  script_tag(name:"last_modification", value:"2025-08-15 05:40:49 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-16 18:54:37 +0000 (Fri, 16 Feb 2024)");

  script_name("Ubuntu: Security Advisory (USN-3487-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU17\.10");

  script_xref(name:"Advisory-ID", value:"USN-3487-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3487-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-raspi2' package(s) announced via the USN-3487-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the KVM subsystem in the Linux kernel did not
properly keep track of nested levels in guest page tables. A local attacker
in a guest VM could use this to cause a denial of service (host OS crash)
or possibly execute arbitrary code in the host OS. (CVE-2017-12188)

It was discovered that on the PowerPC architecture, the kernel did not
properly sanitize the signal stack when handling sigreturn(). A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2017-1000255)

Bo Zhang discovered that the netlink wireless configuration interface in
the Linux kernel did not properly validate attributes when handling certain
requests. A local attacker with the CAP_NET_ADMIN could use this to cause a
denial of service (system crash). (CVE-2017-12153)

It was discovered that the nested KVM implementation in the Linux kernel in
some situations did not properly prevent second level guests from reading
and writing the hardware CR8 register. A local attacker in a guest could
use this to cause a denial of service (system crash). (CVE-2017-12154)

Vitaly Mayatskikh discovered that the SCSI subsystem in the Linux kernel
did not properly track reference counts when merging buffers. A local
attacker could use this to cause a denial of service (memory exhaustion).
(CVE-2017-12190)

It was discovered that the key management subsystem in the Linux kernel did
not properly restrict key reads on negatively instantiated keys. A local
attacker could use this to cause a denial of service (system crash).
(CVE-2017-12192)

It was discovered that the ATI Radeon framebuffer driver in the Linux
kernel did not properly initialize a data structure returned to user space.
A local attacker could use this to expose sensitive information (kernel
memory). (CVE-2017-14156)

ChunYu Wang discovered that the iSCSI transport implementation in the Linux
kernel did not properly validate data structures. A local attacker could
use this to cause a denial of service (system crash). (CVE-2017-14489)

Alexander Potapenko discovered an information leak in the waitid
implementation of the Linux kernel. A local attacker could use this to
expose sensitive information (kernel memory). (CVE-2017-14954)

It was discovered that a race condition existed in the ALSA subsystem of
the Linux kernel when creating and deleting a port via ioctl(). A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2017-15265)

Dmitry Vyukov discovered that the Floating Point Unit (fpu) subsystem in
the Linux kernel did not properly handle attempts to set reserved bits in a
task's extended state (xstate) area. A local attacker could use this to
cause a denial of service (system crash). (CVE-2017-15537)

It was discovered that a race condition existed in the packet fanout
implementation in the Linux kernel. A local ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux, linux-raspi2' package(s) on Ubuntu 17.10.");

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

if(release == "UBUNTU17.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.13.0-1006-raspi2", ver:"4.13.0-1006.6", rls:"UBUNTU17.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.13.0-17-generic", ver:"4.13.0-17.20", rls:"UBUNTU17.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.13.0-17-generic-lpae", ver:"4.13.0-17.20", rls:"UBUNTU17.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.13.0-17-lowlatency", ver:"4.13.0-17.20", rls:"UBUNTU17.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"4.13.0.17.18", rls:"UBUNTU17.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"4.13.0.17.18", rls:"UBUNTU17.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"4.13.0.17.18", rls:"UBUNTU17.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi2", ver:"4.13.0.1006.4", rls:"UBUNTU17.10"))) {
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
