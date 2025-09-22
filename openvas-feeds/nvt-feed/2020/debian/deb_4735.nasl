# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704735");
  script_cve_id("CVE-2020-10713", "CVE-2020-14308", "CVE-2020-14309", "CVE-2020-14310", "CVE-2020-14311", "CVE-2020-15706", "CVE-2020-15707");
  script_tag(name:"creation_date", value:"2020-07-30 03:00:09 +0000 (Thu, 30 Jul 2020)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-05 14:34:24 +0000 (Wed, 05 Aug 2020)");

  script_name("Debian: Security Advisory (DSA-4735-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4735-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/DSA-4735-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4735");
  script_xref(name:"URL", value:"https://www.eclypsium.com/2020/07/29/theres-a-hole-in-the-boot/");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020-GRUB-UEFI-SecureBoot");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/grub2");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'grub2' package(s) announced via the DSA-4735-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the GRUB2 bootloader.

CVE-2020-10713

A flaw in the grub.cfg parsing code was found allowing to break UEFI Secure Boot and load arbitrary code. Details can be found at [link moved to references]

CVE-2020-14308

It was discovered that grub_malloc does not validate the allocation size allowing for arithmetic overflow and subsequently a heap-based buffer overflow.

CVE-2020-14309

An integer overflow in grub_squash_read_symlink may lead to a heap based buffer overflow.

CVE-2020-14310

An integer overflow in read_section_from_string may lead to a heap based buffer overflow.

CVE-2020-14311

An integer overflow in grub_ext2_read_link may lead to a heap-based buffer overflow.

CVE-2020-15706

script: Avoid a use-after-free when redefining a function during execution.

CVE-2020-15707

An integer overflow flaw was found in the initrd size handling.

Further detailed information can be found at [link moved to references]

For the stable distribution (buster), these problems have been fixed in version 2.02+dfsg1-20+deb10u1.

We recommend that you upgrade your grub2 packages.

For the detailed security status of grub2 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'grub2' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"grub-common", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-coreboot", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-coreboot-bin", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-coreboot-dbg", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-amd64", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-amd64-bin", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-amd64-dbg", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-amd64-signed-template", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-arm", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-arm-bin", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-arm-dbg", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-arm64", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-arm64-bin", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-arm64-dbg", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-arm64-signed-template", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-ia32", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-ia32-bin", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-ia32-dbg", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-ia32-signed-template", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-emu", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-emu-dbg", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-firmware-qemu", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-ieee1275", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-ieee1275-bin", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-ieee1275-dbg", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-linuxbios", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-mount-udeb", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-pc", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-pc-bin", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-pc-dbg", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-rescue-pc", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-theme-starfield", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-uboot", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-uboot-bin", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-uboot-dbg", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-xen", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-xen-bin", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-xen-dbg", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-xen-host", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-yeeloong", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-yeeloong-bin", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-yeeloong-dbg", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub2", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub2-common", ver:"2.02+dfsg1-20+deb10u1", rls:"DEB10"))) {
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
