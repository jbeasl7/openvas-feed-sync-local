# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7744.1");
  script_cve_id("CVE-2024-3446", "CVE-2024-3447", "CVE-2024-3567", "CVE-2024-4467", "CVE-2024-6505", "CVE-2024-7409", "CVE-2024-8354");
  script_tag(name:"creation_date", value:"2025-09-16 04:04:41 +0000 (Tue, 16 Sep 2025)");
  script_version("2025-09-16T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-09 20:15:10 +0000 (Tue, 09 Apr 2024)");

  script_name("Ubuntu: Security Advisory (USN-7744-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|24\.04\ LTS|25\.04)");

  script_xref(name:"Advisory-ID", value:"USN-7744-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7744-1");
  script_xref(name:"URL", value:"https://bugs.launchpad.net/bugs/2120814");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu' package(s) announced via the USN-7744-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that QEMU incorrectly handled certain virtio devices. A
privileged guest attacker could use this issue to cause QEMU to crash,
leading to a denial of service, or possibly execute arbitrary code. This
issue only affected Ubuntu 22.04 LTS and Ubuntu 24.04 LTS. (CVE-2024-3446)

It was discovered that QEMU incorrectly handled SDHCI device emulation. A
guest attacker could possibly use this issue to cause QEMU to crash,
leading to a denial of service. This issue only affected Ubuntu 22.04 LTS
and Ubuntu 24.04 LTS. (CVE-2024-3447)

It was discovered that QEMU incorrectly handled calculating the checksum
of a short-sized fragmented packet. A guest attacker could possibly use
this issue to cause QEMU to crash, leading to a denial of service. This
issue only affected Ubuntu 24.04 LTS. (CVE-2024-3567)

It was discovered that the QEMU qemu-img utility incorrectly handled
certain crafted image files. An attacker could use this issue to cause QEMU
to consume resources, leading to a denial of service, or possibly read and
write to an existing external file. This issue only affected Ubuntu 22.04
LTS and Ubuntu 24.04 LTS. (CVE-2024-4467)

It was discovered that QEMU incorrectly handled the RSS feature on
virtio-net devices. A privileged guest attacker could possibly use this
issue to cause QEMU to crash, leading to a denial of service. This
issue only affected Ubuntu 22.04 LTS and Ubuntu 24.04 LTS. (CVE-2024-6505)

It was discovered that QEMU incorrectly handled the NBD server. An attacker
could use this issue to cause QEMU to consume resources, leading to a
denial of service. This issue only affected Ubuntu 22.04 LTS and Ubuntu
24.04 LTS. (CVE-2024-7409)

It was discovered that QEMU incorrectly handled certain USB devices. A
guest attacker could possibly use this issue to cause QEMU to crash,
leading to a denial of service. This issue only affected Ubuntu 22.04 LTS
and Ubuntu 24.04 LTS. (CVE-2024-8354)

It was discovered that the QEMU package incorrectly set up a binfmt_misc
registration with the C (Credential) flag. A local attacker could use this
with a suid/sgid binary to escalate privileges. This update will no longer
run foreign-architecture binaries with suid/sgid with elevated privileges.");

  script_tag(name:"affected", value:"'qemu' package(s) on Ubuntu 22.04, Ubuntu 24.04, Ubuntu 25.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system", ver:"1:6.2+dfsg-2ubuntu6.27", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-arm", ver:"1:6.2+dfsg-2ubuntu6.27", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-mips", ver:"1:6.2+dfsg-2ubuntu6.27", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-misc", ver:"1:6.2+dfsg-2ubuntu6.27", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"1:6.2+dfsg-2ubuntu6.27", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-s390x", ver:"1:6.2+dfsg-2ubuntu6.27", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"1:6.2+dfsg-2ubuntu6.27", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:6.2+dfsg-2ubuntu6.27", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86-microvm", ver:"1:6.2+dfsg-2ubuntu6.27", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86-xen", ver:"1:6.2+dfsg-2ubuntu6.27", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system", ver:"1:8.2.2+ds-0ubuntu1.10", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-arm", ver:"1:8.2.2+ds-0ubuntu1.10", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-mips", ver:"1:8.2.2+ds-0ubuntu1.10", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-misc", ver:"1:8.2.2+ds-0ubuntu1.10", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"1:8.2.2+ds-0ubuntu1.10", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-s390x", ver:"1:8.2.2+ds-0ubuntu1.10", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"1:8.2.2+ds-0ubuntu1.10", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:8.2.2+ds-0ubuntu1.10", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86-xen", ver:"1:8.2.2+ds-0ubuntu1.10", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-xen", ver:"1:8.2.2+ds-0ubuntu1.10", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU25.04") {

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system", ver:"1:9.2.1+ds-1ubuntu5.2", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-arm", ver:"1:9.2.1+ds-1ubuntu5.2", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-mips", ver:"1:9.2.1+ds-1ubuntu5.2", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-misc", ver:"1:9.2.1+ds-1ubuntu5.2", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"1:9.2.1+ds-1ubuntu5.2", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-riscv", ver:"1:9.2.1+ds-1ubuntu5.2", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-s390x", ver:"1:9.2.1+ds-1ubuntu5.2", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"1:9.2.1+ds-1ubuntu5.2", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:9.2.1+ds-1ubuntu5.2", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86-xen", ver:"1:9.2.1+ds-1ubuntu5.2", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-xen", ver:"1:9.2.1+ds-1ubuntu5.2", rls:"UBUNTU25.04"))) {
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
