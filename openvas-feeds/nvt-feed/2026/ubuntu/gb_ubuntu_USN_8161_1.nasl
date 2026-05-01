# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8161.1");
  script_cve_id("CVE-2024-6519", "CVE-2026-2243", "CVE-2026-3195", "CVE-2026-3196", "CVE-2026-3842");
  script_tag(name:"creation_date", value:"2026-04-13 07:50:16 +0000 (Mon, 13 Apr 2026)");
  script_version("2026-04-14T06:16:47+0000");
  script_tag(name:"last_modification", value:"2026-04-14 06:16:47 +0000 (Tue, 14 Apr 2026)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-19 18:25:00 +0000 (Thu, 19 Feb 2026)");

  script_name("Ubuntu: Security Advisory (USN-8161-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|24\.04\ LTS|25\.10)");

  script_xref(name:"Advisory-ID", value:"USN-8161-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8161-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu' package(s) announced via the USN-8161-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the LSI53C895A SCSI Host Bus Adapter implementation
of QEMU incorrectly handled memory. An attacker inside the guest could
possibly use this issue to cause QEMU to crash, resulting in a denial of
service, or possibly execute arbitrary code. (CVE-2024-6519)

It was discovered that QEMU could be made to read out of bounds when
reading VMDK images. If a user or an automated system were tricked into
opening a specially crafted VMDK image, an attacker could possibly use
this issue to leak sensitive informaton or cause QEMU to crash, resulting
in a denial of service. (CVE-2026-2243)

It was discovered that the virtio-snd device implementation of QEMU could
be made to write out of bounds. An attacker inside the guest could
possibly use this issue to cause QEMU to crash, resulting in a denial of
service, or possibly execute arbitrary code. This issue only affected
Ubuntu 24.04 LTS and Ubuntu 25.10. (CVE-2026-3195)

It was discovered that the virtio-snd device implementation of QEMU
contained an arithmetic overflow. An attacker inside the guest could
possibly use this issue to cause QEMU to crash, resulting in a denial of
service, or possibly execute arbitrary code. This issue only affected
Ubuntu 24.04 LTS and Ubuntu 25.10. (CVE-2026-3196)

It was discovered that the Hyper-V Synthetic Debugging device
implementation of QEMU could me made to write out of bounds. An attacker
inside the guest could possibly use this issue to cause QEMU to crash,
resulting in a denial of service, or possibly execute arbitrary code. This
issue only affected Ubuntu 24.04 LTS and Ubuntu 25.10. (CVE-2026-3842)");

  script_tag(name:"affected", value:"'qemu' package(s) on Ubuntu 22.04, Ubuntu 24.04, Ubuntu 25.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"qemu", ver:"1:6.2+dfsg-2ubuntu6.30", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system", ver:"1:6.2+dfsg-2ubuntu6.30", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-arm", ver:"1:6.2+dfsg-2ubuntu6.30", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-common", ver:"1:6.2+dfsg-2ubuntu6.30", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-data", ver:"1:6.2+dfsg-2ubuntu6.30", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-gui", ver:"1:6.2+dfsg-2ubuntu6.30", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-mips", ver:"1:6.2+dfsg-2ubuntu6.30", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-misc", ver:"1:6.2+dfsg-2ubuntu6.30", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"1:6.2+dfsg-2ubuntu6.30", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-s390x", ver:"1:6.2+dfsg-2ubuntu6.30", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"1:6.2+dfsg-2ubuntu6.30", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:6.2+dfsg-2ubuntu6.30", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86-microvm", ver:"1:6.2+dfsg-2ubuntu6.30", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86-xen", ver:"1:6.2+dfsg-2ubuntu6.30", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU24.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system", ver:"1:8.2.2+ds-0ubuntu1.16", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-arm", ver:"1:8.2.2+ds-0ubuntu1.16", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-common", ver:"1:8.2.2+ds-0ubuntu1.16", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-data", ver:"1:8.2.2+ds-0ubuntu1.16", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-gui", ver:"1:8.2.2+ds-0ubuntu1.16", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-mips", ver:"1:8.2.2+ds-0ubuntu1.16", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-misc", ver:"1:8.2.2+ds-0ubuntu1.16", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-modules-opengl", ver:"1:8.2.2+ds-0ubuntu1.16", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-modules-spice", ver:"1:8.2.2+ds-0ubuntu1.16", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"1:8.2.2+ds-0ubuntu1.16", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-s390x", ver:"1:8.2.2+ds-0ubuntu1.16", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"1:8.2.2+ds-0ubuntu1.16", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:8.2.2+ds-0ubuntu1.16", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86-xen", ver:"1:8.2.2+ds-0ubuntu1.16", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-xen", ver:"1:8.2.2+ds-0ubuntu1.16", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU25.10") {

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system", ver:"1:10.1.0+ds-5ubuntu2.6", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-arm", ver:"1:10.1.0+ds-5ubuntu2.6", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-common", ver:"1:10.1.0+ds-5ubuntu2.6", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-data", ver:"1:10.1.0+ds-5ubuntu2.6", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-gui", ver:"1:10.1.0+ds-5ubuntu2.6", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-mips", ver:"1:10.1.0+ds-5ubuntu2.6", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-misc", ver:"1:10.1.0+ds-5ubuntu2.6", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-modules-opengl", ver:"1:10.1.0+ds-5ubuntu2.6", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-modules-spice", ver:"1:10.1.0+ds-5ubuntu2.6", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"1:10.1.0+ds-5ubuntu2.6", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-riscv", ver:"1:10.1.0+ds-5ubuntu2.6", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-s390x", ver:"1:10.1.0+ds-5ubuntu2.6", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"1:10.1.0+ds-5ubuntu2.6", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:10.1.0+ds-5ubuntu2.6", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86-xen", ver:"1:10.1.0+ds-5ubuntu2.6", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-xen", ver:"1:10.1.0+ds-5ubuntu2.6", rls:"UBUNTU25.10"))) {
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
