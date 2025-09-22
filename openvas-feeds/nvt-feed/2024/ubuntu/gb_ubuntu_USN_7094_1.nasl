# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.7094.1");
  script_cve_id("CVE-2019-20382", "CVE-2020-13765", "CVE-2020-1983", "CVE-2020-7039", "CVE-2020-8608", "CVE-2021-3592", "CVE-2021-3594", "CVE-2023-3019", "CVE-2024-4693", "CVE-2024-7730");
  script_tag(name:"creation_date", value:"2024-11-11 04:08:08 +0000 (Mon, 11 Nov 2024)");
  script_version("2025-08-06T05:45:41+0000");
  script_tag(name:"last_modification", value:"2025-08-06 05:45:41 +0000 (Wed, 06 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-05 18:26:29 +0000 (Tue, 05 Aug 2025)");

  script_name("Ubuntu: Security Advisory (USN-7094-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|24\.04\ LTS|24\.10)");

  script_xref(name:"Advisory-ID", value:"USN-7094-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7094-1");
  script_xref(name:"URL", value:"https://bugs.launchpad.net/ubuntu/+source/qemu/+bug/2084210");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu' package(s) announced via the USN-7094-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that QEMU incorrectly handled memory during certain VNC
operations. A remote attacker could possibly use this issue to cause QEMU
to consume resources, resulting in a denial of service. This issue only
affected Ubuntu 14.04 LTS. (CVE-2019-20382)

It was discovered that QEMU incorrectly handled certain memory copy
operations when loading ROM contents. If a user were tricked into running
an untrusted kernel image, a remote attacker could possibly use this issue
to run arbitrary code. This issue only affected Ubuntu 14.04 LTS.
(CVE-2020-13765)

Aviv Sasson discovered that QEMU incorrectly handled Slirp networking. A
remote attacker could use this issue to cause QEMU to crash, resulting in a
denial of service, or possibly execute arbitrary code. This issue only
affected Ubuntu 14.04 LTS. (CVE-2020-1983)

It was discovered that the SLiRP networking implementation of the QEMU
emulator did not properly manage memory under certain circumstances. An
attacker could use this to cause a heap-based buffer overflow or other out-
of-bounds access, which can lead to a denial of service (application crash)
or potential execute arbitrary code. This issue only affected
Ubuntu 14.04 LTS. (CVE-2020-7039)

It was discovered that the SLiRP networking implementation of the QEMU
emulator misuses snprintf return values. An attacker could use this to
cause a denial of service (application crash) or potentially execute
arbitrary code. This issue only affected Ubuntu 14.04 LTS. (CVE-2020-8608)

It was discovered that QEMU SLiRP networking incorrectly handled certain
udp packets. An attacker inside a guest could possibly use this issue to
leak sensitive information from the host. This issue only affected
Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. (CVE-2021-3592, CVE-2021-3594)

It was discovered that QEMU had a DMA reentrancy issue, leading to a
use-after-free vulnerability. An attacker could possibly use this issue
to cause a denial of service. This issue only affected Ubuntu 18.04 LTS,
Ubuntu 20.04 LTS and Ubuntu 22.04 LTS. (CVE-2023-3019)

It was discovered that QEMU had a flaw in Virtio PCI Bindings, leading
to a triggerable crash via vhost_net_stop. An attacker inside a guest
could possibly use this issue to cause a denial of service. This issue
only affected Ubuntu 24.04 LTS and Ubuntu 24.10. (CVE-2024-4693)

It was discovered that QEMU incorrectly handled memory in virtio-sound,
leading to a heap-based buffer overflow. An attacker could possibly use
this issue to cause a denial of service or execute arbitrary code. This
issue only affected Ubuntu 24.04 LTS and Ubuntu 24.10. (CVE-2024-7730)");

  script_tag(name:"affected", value:"'qemu' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04, Ubuntu 24.10.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"qemu", ver:"2.0.0+dfsg-2ubuntu1.47+esm4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system", ver:"2.0.0+dfsg-2ubuntu1.47+esm4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-aarch64", ver:"2.0.0+dfsg-2ubuntu1.47+esm4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-arm", ver:"2.0.0+dfsg-2ubuntu1.47+esm4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-common", ver:"2.0.0+dfsg-2ubuntu1.47+esm4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-mips", ver:"2.0.0+dfsg-2ubuntu1.47+esm4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-misc", ver:"2.0.0+dfsg-2ubuntu1.47+esm4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"2.0.0+dfsg-2ubuntu1.47+esm4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"2.0.0+dfsg-2ubuntu1.47+esm4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"2.0.0+dfsg-2ubuntu1.47+esm4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"qemu", ver:"1:2.5+dfsg-5ubuntu10.51+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system", ver:"1:2.5+dfsg-5ubuntu10.51+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-aarch64", ver:"1:2.5+dfsg-5ubuntu10.51+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-arm", ver:"1:2.5+dfsg-5ubuntu10.51+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-common", ver:"1:2.5+dfsg-5ubuntu10.51+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-mips", ver:"1:2.5+dfsg-5ubuntu10.51+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-misc", ver:"1:2.5+dfsg-5ubuntu10.51+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"1:2.5+dfsg-5ubuntu10.51+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-s390x", ver:"1:2.5+dfsg-5ubuntu10.51+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"1:2.5+dfsg-5ubuntu10.51+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:2.5+dfsg-5ubuntu10.51+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"qemu", ver:"1:2.11+dfsg-1ubuntu7.42+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system", ver:"1:2.11+dfsg-1ubuntu7.42+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-arm", ver:"1:2.11+dfsg-1ubuntu7.42+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-mips", ver:"1:2.11+dfsg-1ubuntu7.42+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-misc", ver:"1:2.11+dfsg-1ubuntu7.42+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"1:2.11+dfsg-1ubuntu7.42+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-s390x", ver:"1:2.11+dfsg-1ubuntu7.42+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"1:2.11+dfsg-1ubuntu7.42+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:2.11+dfsg-1ubuntu7.42+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"qemu", ver:"1:4.2-3ubuntu6.30", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system", ver:"1:4.2-3ubuntu6.30", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-arm", ver:"1:4.2-3ubuntu6.30", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-mips", ver:"1:4.2-3ubuntu6.30", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-misc", ver:"1:4.2-3ubuntu6.30", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"1:4.2-3ubuntu6.30", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-s390x", ver:"1:4.2-3ubuntu6.30", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"1:4.2-3ubuntu6.30", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:4.2-3ubuntu6.30", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86-microvm", ver:"1:4.2-3ubuntu6.30", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86-xen", ver:"1:4.2-3ubuntu6.30", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"qemu", ver:"1:6.2+dfsg-2ubuntu6.24", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system", ver:"1:6.2+dfsg-2ubuntu6.24", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-arm", ver:"1:6.2+dfsg-2ubuntu6.24", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-mips", ver:"1:6.2+dfsg-2ubuntu6.24", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-misc", ver:"1:6.2+dfsg-2ubuntu6.24", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"1:6.2+dfsg-2ubuntu6.24", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-s390x", ver:"1:6.2+dfsg-2ubuntu6.24", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"1:6.2+dfsg-2ubuntu6.24", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:6.2+dfsg-2ubuntu6.24", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86-microvm", ver:"1:6.2+dfsg-2ubuntu6.24", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86-xen", ver:"1:6.2+dfsg-2ubuntu6.24", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system", ver:"1:8.2.2+ds-0ubuntu1.4", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-arm", ver:"1:8.2.2+ds-0ubuntu1.4", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-mips", ver:"1:8.2.2+ds-0ubuntu1.4", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-misc", ver:"1:8.2.2+ds-0ubuntu1.4", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"1:8.2.2+ds-0ubuntu1.4", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-s390x", ver:"1:8.2.2+ds-0ubuntu1.4", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"1:8.2.2+ds-0ubuntu1.4", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:8.2.2+ds-0ubuntu1.4", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86-xen", ver:"1:8.2.2+ds-0ubuntu1.4", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-xen", ver:"1:8.2.2+ds-0ubuntu1.4", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU24.10") {

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system", ver:"1:9.0.2+ds-4ubuntu5.1", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-arm", ver:"1:9.0.2+ds-4ubuntu5.1", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-mips", ver:"1:9.0.2+ds-4ubuntu5.1", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-misc", ver:"1:9.0.2+ds-4ubuntu5.1", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"1:9.0.2+ds-4ubuntu5.1", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-s390x", ver:"1:9.0.2+ds-4ubuntu5.1", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"1:9.0.2+ds-4ubuntu5.1", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:9.0.2+ds-4ubuntu5.1", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86-xen", ver:"1:9.0.2+ds-4ubuntu5.1", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-xen", ver:"1:9.0.2+ds-4ubuntu5.1", rls:"UBUNTU24.10"))) {
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
