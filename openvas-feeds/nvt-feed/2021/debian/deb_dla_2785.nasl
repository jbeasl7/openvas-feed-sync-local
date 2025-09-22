# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892785");
  script_cve_id("CVE-2020-16119", "CVE-2020-3702", "CVE-2021-22543", "CVE-2021-33624", "CVE-2021-3444", "CVE-2021-34556", "CVE-2021-35039", "CVE-2021-35477", "CVE-2021-3600", "CVE-2021-3612", "CVE-2021-3653", "CVE-2021-3655", "CVE-2021-3656", "CVE-2021-3679", "CVE-2021-37159", "CVE-2021-3732", "CVE-2021-3743", "CVE-2021-3753", "CVE-2021-37576", "CVE-2021-38160", "CVE-2021-38198", "CVE-2021-38199", "CVE-2021-38204", "CVE-2021-38205", "CVE-2021-40490", "CVE-2021-42008", "CVE-2021-42252");
  script_tag(name:"creation_date", value:"2021-10-16 01:00:36 +0000 (Sat, 16 Oct 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-10 18:55:35 +0000 (Thu, 10 Mar 2022)");

  script_name("Debian: Security Advisory (DLA-2785-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2785-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/DLA-2785-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux-4.19");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-4.19' package(s) announced via the DLA-2785-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2020-3702

A flaw was found in the driver for Atheros IEEE 802.11n family of chipsets (ath9k) allowing information disclosure.

CVE-2020-16119

Hadar Manor reported a use-after-free in the DCCP protocol implementation in the Linux kernel. A local attacker can take advantage of this flaw to cause a denial of service or potentially to execute arbitrary code.

CVE-2021-3444

, CVE-2021-3600

Two flaws were discovered in the Extended BPF (eBPF) verifier. A local user could exploit these to read and write arbitrary memory in the kernel, which could be used for privilege escalation.

This can be mitigated by setting sysctl kernel.unprivileged_bpf_disabled=1, which disables eBPF use by unprivileged users.

CVE-2021-3612

Murray McAllister reported a flaw in the joystick input subsystem. A local user permitted to access a joystick device could exploit this to read and write out-of-bounds in the kernel, which could be used for privilege escalation.

CVE-2021-3653

Maxim Levitsky discovered a vulnerability in the KVM hypervisor implementation for AMD processors in the Linux kernel: Missing validation of the `int_ctl` VMCB field could allow a malicious L1 guest to enable AVIC support (Advanced Virtual Interrupt Controller) for the L2 guest. The L2 guest can take advantage of this flaw to write to a limited but still relatively large subset of the host physical memory.

CVE-2021-3655

Ilja Van Sprundel and Marcelo Ricardo Leitner found multiple flaws in the SCTP implementation, where missing validation could lead to an out-of-bounds read. On a system using SCTP, a networked attacker could exploit these to cause a denial of service (crash).

CVE-2021-3656

Maxim Levitsky and Paolo Bonzini discovered a flaw in the KVM hypervisor implementation for AMD processors in the Linux kernel. Missing validation of the `virt_ext` VMCB field could allow a malicious L1 guest to disable both VMLOAD/VMSAVE intercepts and VLS (Virtual VMLOAD/VMSAVE) for the L2 guest. Under these circumstances, the L2 guest is able to run VMLOAD/VMSAVE unintercepted and thus read/write portions of the host's physical memory.

CVE-2021-3679

A flaw in the Linux kernel tracing module functionality could allow a privileged local user (with CAP_SYS_ADMIN capability) to cause a denial of service (resource starvation).

CVE-2021-3732

Alois Wohlschlager reported a flaw in the implementation of the overlayfs subsystem, allowing a local attacker with privileges to mount a filesystem to reveal files hidden in the original mount.

CVE-2021-3743

An out-of-bounds memory read was discovered in the Qualcomm IPC router protocol implementation, allowing to cause a denial of service or information leak.

CVE-2021-3753

Minh Yuan reported a race condition in the vt_k_ioctl in ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-4.19' package(s) on Debian 9.");

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

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-config-4.19", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-4.19", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.18-686", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.18-686-pae", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.18-all", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.18-all-amd64", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.18-all-arm64", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.18-all-armel", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.18-all-armhf", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.18-all-i386", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.18-amd64", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.18-arm64", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.18-armmp", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.18-armmp-lpae", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.18-cloud-amd64", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.18-common", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.18-common-rt", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.18-marvell", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.18-rpi", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.18-rt-686-pae", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.18-rt-amd64", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.18-rt-arm64", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-0.bpo.18-rt-armmp", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-686", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-686-dbg", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-686-pae", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-686-pae-dbg", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-amd64", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-amd64-dbg", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-arm64", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-arm64-dbg", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-armmp", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-armmp-dbg", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-armmp-lpae", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-armmp-lpae-dbg", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-cloud-amd64", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-cloud-amd64-dbg", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-marvell", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-marvell-dbg", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-rpi", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-rpi-dbg", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-rt-686-pae", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-rt-686-pae-dbg", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-rt-amd64", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-rt-amd64-dbg", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-rt-arm64", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-rt-arm64-dbg", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-rt-armmp", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-0.bpo.18-rt-armmp-dbg", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-kbuild-4.19", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-perf-4.19", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-4.19", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-support-4.19.0-0.bpo.18", ver:"4.19.208-1~deb9u1", rls:"DEB9"))) {
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
