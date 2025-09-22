# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704465");
  script_cve_id("CVE-2019-10126", "CVE-2019-11477", "CVE-2019-11478", "CVE-2019-11479", "CVE-2019-11486", "CVE-2019-11599", "CVE-2019-11815", "CVE-2019-11833", "CVE-2019-11884", "CVE-2019-3846", "CVE-2019-5489", "CVE-2019-9500", "CVE-2019-9503");
  script_tag(name:"creation_date", value:"2019-06-18 02:00:15 +0000 (Tue, 18 Jun 2019)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-17 14:11:17 +0000 (Mon, 17 Jun 2019)");

  script_name("Debian: Security Advisory (DSA-4465-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4465-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/DSA-4465-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4465");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-4465-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2019-3846, CVE-2019-10126 huangwen reported multiple buffer overflows in the Marvell wifi (mwifiex) driver, which a local user could use to cause denial of service or the execution of arbitrary code.

CVE-2019-5489

Daniel Gruss, Erik Kraft, Trishita Tiwari, Michael Schwarz, Ari Trachtenberg, Jason Hennessey, Alex Ionescu, and Anders Fogh discovered that local users could use the mincore() system call to obtain sensitive information from other processes that access the same memory-mapped file.

CVE-2019-9500, CVE-2019-9503 Hugues Anguelkov discovered a buffer overflow and missing access validation in the Broadcom FullMAC wifi driver (brcmfmac), which a attacker on the same wifi network could use to cause denial of service or the execution of arbitrary code.

CVE-2019-11477

Jonathan Looney reported that a specially crafted sequence of TCP selective acknowledgements (SACKs) allows a remotely triggerable kernel panic.

CVE-2019-11478

Jonathan Looney reported that a specially crafted sequence of TCP selective acknowledgements (SACKs) will fragment the TCP retransmission queue, allowing an attacker to cause excessive resource usage.

CVE-2019-11479

Jonathan Looney reported that an attacker could force the Linux kernel to segment its responses into multiple TCP segments, each of which contains only 8 bytes of data, drastically increasing the bandwidth required to deliver the same amount of data.

This update introduces a new sysctl value to control the minimal MSS (net.ipv4.tcp_min_snd_mss), which by default uses the formerly hard coded value of 48. We recommend raising this to 536 unless you know that your network requires a lower value.

CVE-2019-11486

Jann Horn of Google reported numerous race conditions in the Siemens R3964 line discipline. A local user could use these to cause unspecified security impact. This module has therefore been disabled.

CVE-2019-11599

Jann Horn of Google reported a race condition in the core dump implementation which could lead to a use-after-free. A local user could use this to read sensitive information, to cause a denial of service (memory corruption), or for privilege escalation.

CVE-2019-11815

It was discovered that a use-after-free in the Reliable Datagram Sockets protocol could result in denial of service and potentially privilege escalation. This protocol module (rds) is not auto loaded on Debian systems, so this issue only affects systems where it is explicitly loaded.

CVE-2019-11833

It was discovered that the ext4 filesystem implementation writes uninitialised data from kernel memory to new extent blocks. A local user able to write to an ext4 filesystem and then read the filesystem image, for example using a removable drive, might be able to use this to obtain sensitive ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"acpi-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"acpi-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"acpi-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-4.9.0-9-4kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-4.9.0-9-5kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-4.9.0-9-loongson-3-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-4.9.0-9-octeon-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-4.9.0-9-4kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-4.9.0-9-5kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-4.9.0-9-arm64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-4.9.0-9-armmp-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-4.9.0-9-loongson-3-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-4.9.0-9-powerpc64le-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.9.0-9-4kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.9.0-9-5kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.9.0-9-arm64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.9.0-9-armmp-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.9.0-9-loongson-3-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.9.0-9-marvell-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.9.0-9-octeon-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.9.0-9-powerpc64le-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.9.0-9-s390x-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.9.0-9-4kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.9.0-9-5kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.9.0-9-arm64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.9.0-9-loongson-3-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.9.0-9-marvell-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.9.0-9-octeon-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.9.0-9-powerpc64le-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.9.0-9-4kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.9.0-9-5kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.9.0-9-arm64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.9.0-9-armmp-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.9.0-9-loongson-3-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.9.0-9-marvell-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.9.0-9-octeon-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.9.0-9-powerpc64le-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.9.0-9-s390x-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.9.0-9-4kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.9.0-9-5kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.9.0-9-arm64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.9.0-9-armmp-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.9.0-9-loongson-3-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.9.0-9-marvell-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.9.0-9-octeon-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.9.0-9-powerpc64le-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.9.0-9-s390x-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.9.0-9-4kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.9.0-9-5kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.9.0-9-arm64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.9.0-9-armmp-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.9.0-9-loongson-3-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.9.0-9-marvell-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.9.0-9-octeon-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.9.0-9-powerpc64le-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.9.0-9-s390x-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dasd-extra-modules-4.9.0-9-s390x-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dasd-modules-4.9.0-9-s390x-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-modules-4.9.0-9-arm64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-modules-4.9.0-9-armmp-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.9.0-9-4kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.9.0-9-5kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.9.0-9-arm64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.9.0-9-armmp-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.9.0-9-loongson-3-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.9.0-9-marvell-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.9.0-9-octeon-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.9.0-9-powerpc64le-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.9.0-9-4kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.9.0-9-5kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.9.0-9-arm64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.9.0-9-armmp-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.9.0-9-loongson-3-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.9.0-9-marvell-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.9.0-9-octeon-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.9.0-9-powerpc64le-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.9.0-9-s390x-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fancontrol-modules-4.9.0-9-powerpc64le-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.9.0-9-4kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.9.0-9-5kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.9.0-9-arm64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.9.0-9-armmp-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.9.0-9-loongson-3-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.9.0-9-marvell-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.9.0-9-octeon-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.9.0-9-powerpc64le-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.9.0-9-s390x-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-4.9.0-9-arm64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-4.9.0-9-armmp-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-4.9.0-9-loongson-3-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-4.9.0-9-marvell-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-4.9.0-9-loongson-3-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-4.9.0-9-powerpc64le-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.9.0-9-4kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.9.0-9-5kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.9.0-9-arm64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.9.0-9-armmp-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.9.0-9-loongson-3-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.9.0-9-marvell-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.9.0-9-octeon-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.9.0-9-powerpc64le-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.9.0-9-s390x-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hfs-modules-4.9.0-9-4kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hfs-modules-4.9.0-9-5kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hfs-modules-4.9.0-9-loongson-3-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hfs-modules-4.9.0-9-octeon-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hyperv-daemons", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hyperv-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hyperv-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hyperv-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hypervisor-modules-4.9.0-9-powerpc64le-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-4.9.0-9-4kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-4.9.0-9-5kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-4.9.0-9-arm64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-4.9.0-9-armmp-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.9.0-9-4kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.9.0-9-5kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.9.0-9-arm64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.9.0-9-armmp-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.9.0-9-loongson-3-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.9.0-9-marvell-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.9.0-9-octeon-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.9.0-9-powerpc64le-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-4.9.0-9-marvell-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.9.0-9-4kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.9.0-9-5kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.9.0-9-arm64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.9.0-9-armmp-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.9.0-9-loongson-3-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.9.0-9-marvell-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.9.0-9-octeon-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.9.0-9-powerpc64le-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.9.0-9-s390x-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jffs2-modules-4.9.0-9-marvell-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.9.0-9-4kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.9.0-9-5kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.9.0-9-arm64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.9.0-9-armmp-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.9.0-9-loongson-3-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.9.0-9-marvell-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.9.0-9-octeon-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.9.0-9-powerpc64le-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.9.0-9-4kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.9.0-9-5kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.9.0-9-arm64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.9.0-9-armmp-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.9.0-9-loongson-3-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.9.0-9-marvell-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.9.0-9-octeon-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.9.0-9-powerpc64le-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.9.0-9-s390x-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"leds-modules-4.9.0-9-arm64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"leds-modules-4.9.0-9-armmp-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"leds-modules-4.9.0-9-marvell-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcpupower-dev", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcpupower1", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libusbip-dev", ver:"2.0+4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-6-arm", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-6-s390", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-6-x86", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-cpupower", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-4.9", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-9-4kc-malta", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-9-5kc-malta", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-9-686", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-9-686-pae", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-9-all", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-9-all-amd64", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-9-all-arm64", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-9-all-armel", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-9-all-armhf", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-9-all-i386", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-9-all-mips", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-9-all-mips64el", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-9-all-mipsel", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-9-all-ppc64el", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-9-all-s390x", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-9-amd64", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-9-arm64", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-9-armmp", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-9-armmp-lpae", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-9-common", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-9-common-rt", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-9-loongson-3", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-9-marvell", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-9-octeon", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-9-powerpc64le", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-9-rt-686-pae", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-9-rt-amd64", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-9-s390x", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-9-4kc-malta", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-9-4kc-malta-dbg", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-9-5kc-malta", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-9-5kc-malta-dbg", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-9-686", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-9-686-dbg", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-9-686-pae", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-9-686-pae-dbg", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-9-amd64", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-9-amd64-dbg", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-9-arm64", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-9-arm64-dbg", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-9-armmp", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-9-armmp-dbg", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-9-armmp-lpae", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-9-armmp-lpae-dbg", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-9-loongson-3", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-9-loongson-3-dbg", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-9-marvell", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-9-marvell-dbg", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-9-octeon", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-9-octeon-dbg", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-9-powerpc64le", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-9-powerpc64le-dbg", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-9-rt-686-pae", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-9-rt-686-pae-dbg", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-9-rt-amd64", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-9-rt-amd64-dbg", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-9-s390x", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-9-s390x-dbg", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-kbuild-4.9", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-libc-dev", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-manual-4.9", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-perf-4.9", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-4.9", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-support-4.9.0-9", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.9.0-9-4kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.9.0-9-5kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.9.0-9-arm64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.9.0-9-armmp-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.9.0-9-loongson-3-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.9.0-9-marvell-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.9.0-9-octeon-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.9.0-9-powerpc64le-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.9.0-9-s390x-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.9.0-9-4kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.9.0-9-5kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.9.0-9-arm64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.9.0-9-armmp-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.9.0-9-loongson-3-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.9.0-9-marvell-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.9.0-9-octeon-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.9.0-9-powerpc64le-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.9.0-9-s390x-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-4.9.0-9-4kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-4.9.0-9-5kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-4.9.0-9-loongson-3-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-4.9.0-9-marvell-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-4.9.0-9-octeon-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-4.9.0-9-4kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-4.9.0-9-5kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-4.9.0-9-4kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-4.9.0-9-5kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-4.9.0-9-arm64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-4.9.0-9-armmp-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-4.9.0-9-marvell-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-4.9.0-9-4kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-4.9.0-9-5kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-4.9.0-9-marvell-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-4.9.0-9-powerpc64le-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-modules-4.9.0-9-armmp-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-modules-4.9.0-9-marvell-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.9.0-9-4kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.9.0-9-5kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.9.0-9-arm64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.9.0-9-armmp-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.9.0-9-loongson-3-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.9.0-9-marvell-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.9.0-9-octeon-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.9.0-9-powerpc64le-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.9.0-9-s390x-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.9.0-9-4kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.9.0-9-5kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.9.0-9-arm64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.9.0-9-armmp-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.9.0-9-loongson-3-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.9.0-9-marvell-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.9.0-9-octeon-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.9.0-9-powerpc64le-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.9.0-9-s390x-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nfs-modules-4.9.0-9-loongson-3-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.9.0-9-4kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.9.0-9-5kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.9.0-9-arm64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.9.0-9-armmp-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.9.0-9-loongson-3-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.9.0-9-marvell-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.9.0-9-octeon-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.9.0-9-powerpc64le-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.9.0-9-s390x-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-pcmcia-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-pcmcia-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-pcmcia-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.9.0-9-4kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.9.0-9-5kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.9.0-9-arm64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.9.0-9-armmp-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.9.0-9-loongson-3-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.9.0-9-marvell-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.9.0-9-octeon-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.9.0-9-powerpc64le-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.9.0-9-4kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.9.0-9-5kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.9.0-9-arm64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.9.0-9-armmp-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.9.0-9-loongson-3-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.9.0-9-marvell-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.9.0-9-octeon-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.9.0-9-4kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.9.0-9-5kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.9.0-9-arm64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.9.0-9-armmp-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.9.0-9-loongson-3-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.9.0-9-octeon-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-4.9.0-9-4kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-4.9.0-9-5kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-4.9.0-9-loongson-3-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-4.9.0-9-octeon-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-4.9.0-9-4kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-4.9.0-9-5kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-4.9.0-9-armmp-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-4.9.0-9-loongson-3-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-4.9.0-9-octeon-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-storage-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-storage-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-storage-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.9.0-9-4kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.9.0-9-5kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.9.0-9-arm64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.9.0-9-armmp-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.9.0-9-loongson-3-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.9.0-9-marvell-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.9.0-9-octeon-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.9.0-9-powerpc64le-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rtc-modules-4.9.0-9-octeon-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.9.0-9-4kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.9.0-9-5kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.9.0-9-arm64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.9.0-9-armmp-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.9.0-9-loongson-3-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.9.0-9-marvell-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.9.0-9-octeon-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.9.0-9-powerpc64le-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.9.0-9-4kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.9.0-9-5kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.9.0-9-arm64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.9.0-9-armmp-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.9.0-9-loongson-3-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.9.0-9-marvell-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.9.0-9-octeon-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.9.0-9-powerpc64le-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.9.0-9-s390x-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.9.0-9-4kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.9.0-9-5kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.9.0-9-arm64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.9.0-9-armmp-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.9.0-9-loongson-3-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.9.0-9-octeon-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.9.0-9-powerpc64le-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.9.0-9-s390x-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-4.9.0-9-powerpc64le-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-4.9.0-9-4kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-4.9.0-9-5kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-4.9.0-9-loongson-3-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-4.9.0-9-octeon-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-4.9.0-9-loongson-3-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.9.0-9-4kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.9.0-9-5kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.9.0-9-arm64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.9.0-9-armmp-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.9.0-9-loongson-3-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.9.0-9-marvell-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.9.0-9-octeon-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.9.0-9-powerpc64le-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.9.0-9-4kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.9.0-9-5kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.9.0-9-arm64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.9.0-9-armmp-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.9.0-9-loongson-3-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.9.0-9-marvell-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.9.0-9-octeon-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.9.0-9-powerpc64le-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.9.0-9-s390x-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-4.9.0-9-arm64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-4.9.0-9-armmp-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-4.9.0-9-marvell-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-4.9.0-9-powerpc64le-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.9.0-9-4kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.9.0-9-5kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.9.0-9-arm64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.9.0-9-armmp-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.9.0-9-loongson-3-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.9.0-9-marvell-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.9.0-9-octeon-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.9.0-9-powerpc64le-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.9.0-9-4kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.9.0-9-5kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.9.0-9-loongson-3-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.9.0-9-marvell-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.9.0-9-octeon-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.9.0-9-powerpc64le-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.9.0-9-4kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.9.0-9-5kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.9.0-9-arm64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.9.0-9-armmp-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.9.0-9-loongson-3-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.9.0-9-marvell-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.9.0-9-octeon-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.9.0-9-powerpc64le-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usbip", ver:"2.0+4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-4.9.0-9-4kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-4.9.0-9-5kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-4.9.0-9-arm64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-4.9.0-9-armmp-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-4.9.0-9-loongson-3-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-4.9.0-9-octeon-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-4.9.0-9-powerpc64le-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-4.9.0-9-s390x-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.9.0-9-4kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.9.0-9-5kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.9.0-9-686-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.9.0-9-686-pae-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.9.0-9-amd64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.9.0-9-arm64-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.9.0-9-loongson-3-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.9.0-9-octeon-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.9.0-9-powerpc64le-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.9.0-9-s390x-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-4.9.0-9-4kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-4.9.0-9-5kc-malta-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-4.9.0-9-armmp-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-4.9.0-9-loongson-3-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-4.9.0-9-marvell-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-4.9.0-9-octeon-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-4.9.0-9-s390x-di", ver:"4.9.168-1+deb9u3", rls:"DEB9"))) {
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
