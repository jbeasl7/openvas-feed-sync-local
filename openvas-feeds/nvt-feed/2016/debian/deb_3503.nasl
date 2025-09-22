# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703503");
  script_cve_id("CVE-2013-4312", "CVE-2015-8785", "CVE-2015-8812", "CVE-2015-8816", "CVE-2016-2069", "CVE-2016-2384", "CVE-2016-2543", "CVE-2016-2544", "CVE-2016-2545", "CVE-2016-2546", "CVE-2016-2547", "CVE-2016-2548", "CVE-2016-2549", "CVE-2016-2550", "CVE-2016-2847");
  script_tag(name:"creation_date", value:"2016-03-08 07:07:38 +0000 (Tue, 08 Mar 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-02 17:13:23 +0000 (Mon, 02 May 2016)");

  script_name("Debian: Security Advisory (DSA-3503-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|8)");

  script_xref(name:"Advisory-ID", value:"DSA-3503-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3503-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3503");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-3503-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service, information leak or data loss.

CVE-2013-4312, CVE-2016-2847 Tetsuo Handa discovered that users can use pipes queued on local (Unix) sockets to allocate an unfair share of kernel memory, leading to denial-of-service (resource exhaustion). This issue was previously mitigated for the stable suite by limiting the total number of files queued by each user on local sockets. The new kernel version in both suites includes that mitigation plus limits on the total size of pipe buffers allocated for each user.

CVE-2015-7566

Ralf Spenneberg of OpenSource Security reported that the visor driver crashes when a specially crafted USB device without bulk-out endpoint is detected.

CVE-2015-8767

An SCTP denial-of-service was discovered which can be triggered by a local attacker during a heartbeat timeout event after the 4-way handshake.

CVE-2015-8785

It was discovered that local users permitted to write to a file on a FUSE filesystem could cause a denial of service (unkillable loop in the kernel).

CVE-2015-8812

A flaw was found in the iw_cxgb3 Infiniband driver. Whenever it could not send a packet because the network was congested, it would free the packet buffer but later attempt to send the packet again. This use-after-free could result in a denial of service (crash or hang), data loss or privilege escalation.

CVE-2015-8816

A use-after-free vulnerability was discovered in the USB hub driver. This may be used by a physically present user for privilege escalation.

CVE-2015-8830

Ben Hawkes of Google Project Zero reported that the AIO interface permitted reading or writing 2 GiB of data or more in a single chunk, which could lead to an integer overflow when applied to certain filesystems, socket or device types. The full security impact has not been evaluated.

CVE-2016-0723

A use-after-free vulnerability was discovered in the TIOCGETD ioctl. A local attacker could use this flaw for denial-of-service.

CVE-2016-0774

It was found that the fix for CVE-2015-1805 in kernel versions older than Linux 3.16 did not correctly handle the case of a partially failed atomic read. A local, unprivileged user could use this flaw to crash the system or leak kernel memory to user space.

CVE-2016-2069

Andy Lutomirski discovered a race condition in flushing of the TLB when switching tasks on an x86 system. On an SMP system this could possibly lead to a crash, information leak or privilege escalation.

CVE-2016-2384

Andrey Konovalov found that a crafted USB MIDI device with an invalid USB descriptor could trigger a double-free. This may be used by a physically present user for privilege escalation.

CVE-2016-2543

Dmitry Vyukov found that the core sound sequencer driver (snd-seq) lacked a necessary check for a null pointer, allowing a user with access to a sound sequencer ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 7, Debian 8.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"acpi-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"acpi-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"acpi-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.2.0-4-iop32x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.2.0-4-mx5-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.2.0-4-sparc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-4kc-malta-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-iop32x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-kirkwood-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-loongson-2f-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-mx5-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-orion5x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-sparc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-versatile-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-vexpress-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-4kc-malta-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-iop32x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-kirkwood-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-loongson-2f-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-orion5x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-sparc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-versatile-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.2.0-4-iop32x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.2.0-4-kirkwood-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.2.0-4-mx5-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.2.0-4-orion5x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.2.0-4-s390x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.2.0-4-sparc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.2.0-4-versatile-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.2.0-4-vexpress-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-iop32x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-kirkwood-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-mx5-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-orion5x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-versatile-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-vexpress-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-4kc-malta-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-iop32x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-kirkwood-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-loongson-2f-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-mx5-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-orion5x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-s390x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-sparc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-versatile-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-vexpress-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-4kc-malta-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-iop32x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-kirkwood-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-loongson-2f-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-mx5-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-orion5x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-s390x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-sparc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-versatile-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-vexpress-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dasd-extra-modules-3.2.0-4-s390x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dasd-modules-3.2.0-4-s390x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.2.0-4-iop32x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.2.0-4-kirkwood-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.2.0-4-orion5x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-iop32x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-kirkwood-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-mx5-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-orion5x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-s390x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-sparc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-versatile-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-vexpress-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-iop32x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-kirkwood-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-mx5-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-orion5x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-s390x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-sparc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-versatile-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-vexpress-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-iop32x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-kirkwood-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-mx5-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-orion5x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-s390x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-sparc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-versatile-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-vexpress-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fancontrol-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-4kc-malta-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-iop32x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-kirkwood-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-loongson-2f-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-mx5-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-orion5x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-s390x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-sparc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-versatile-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-vexpress-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-3.2.0-4-kirkwood-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"floppy-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"floppy-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"floppy-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"floppy-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"floppy-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-4kc-malta-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-iop32x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-kirkwood-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-loongson-2f-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-mx5-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-orion5x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-s390x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-sparc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-versatile-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-vexpress-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hfs-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hfs-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hyperv-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hyperv-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hyperv-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hypervisor-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ide-core-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ide-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.2.0-4-4kc-malta-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.2.0-4-kirkwood-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.2.0-4-loongson-2f-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.2.0-4-mx5-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.2.0-4-sparc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.2.0-4-vexpress-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-4kc-malta-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-iop32x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-kirkwood-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-loongson-2f-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-mx5-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-orion5x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-versatile-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-vexpress-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"irda-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"irda-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"irda-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"irda-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"irda-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"irda-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-4kc-malta-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-iop32x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-kirkwood-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-loongson-2f-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-mx5-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-orion5x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-sparc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-versatile-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-vexpress-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jffs2-modules-3.2.0-4-iop32x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jffs2-modules-3.2.0-4-orion5x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-4kc-malta-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-iop32x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-kirkwood-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-loongson-2f-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-mx5-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-orion5x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-sparc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-vexpress-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-4kc-malta-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-iop32x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-kirkwood-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-loongson-2f-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-mx5-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-orion5x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-r4k-ip22-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-r5k-cobalt-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-r5k-ip32-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-s390x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-s390x-tape-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-sparc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-versatile-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-vexpress-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"leds-modules-3.2.0-4-kirkwood-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-3.2", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-486", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-4kc-malta", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-5kc-malta", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-686-pae", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-amd64", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-armel", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-armhf", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-i386", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-ia64", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-mips", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-mipsel", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-powerpc", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-s390", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-s390x", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-sparc", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-amd64", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-common", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-common-rt", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-iop32x", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-itanium", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-ixp4xx", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-kirkwood", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-loongson-2f", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-mckinley", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-mv78xx0", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-mx5", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-octeon", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-omap", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-orion5x", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-powerpc", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-powerpc-smp", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-powerpc64", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-r4k-ip22", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-r5k-cobalt", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-r5k-ip32", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-rt-686-pae", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-rt-amd64", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-s390x", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-sb1-bcm91250a", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-sb1a-bcm91480b", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-sparc64", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-sparc64-smp", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-versatile", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-vexpress", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-486", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-4kc-malta", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-5kc-malta", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-686-pae", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-686-pae-dbg", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-amd64", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-amd64-dbg", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-iop32x", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-itanium", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-ixp4xx", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-kirkwood", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-loongson-2f", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-mckinley", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-mv78xx0", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-mx5", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-octeon", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-omap", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-orion5x", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-powerpc", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-powerpc-smp", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-powerpc64", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-r4k-ip22", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-r5k-cobalt", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-r5k-ip32", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-686-pae", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-686-pae-dbg", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-amd64", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-amd64-dbg", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-s390x", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-s390x-dbg", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-s390x-tape", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-sb1-bcm91250a", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-sb1a-bcm91480b", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-sparc64", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-sparc64-smp", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-versatile", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-vexpress", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-libc-dev", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-manual-3.2", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-3.2", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-support-3.2.0-4", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-4kc-malta-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-iop32x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-kirkwood-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-loongson-2f-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-mx5-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-orion5x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-versatile-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-vexpress-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-4kc-malta-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-iop32x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-kirkwood-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-loongson-2f-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-mx5-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-orion5x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-s390x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-sparc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-versatile-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-vexpress-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-3.2.0-4-kirkwood-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-3.2.0-4-mx5-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-3.2.0-4-orion5x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-3.2.0-4-kirkwood-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-3.2.0-4-mx5-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-3.2.0-4-vexpress-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-3.2.0-4-kirkwood-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-modules-3.2.0-4-mx5-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-4kc-malta-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-iop32x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-kirkwood-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-loongson-2f-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-mx5-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-orion5x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-s390x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-sparc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-versatile-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-vexpress-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-4kc-malta-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-iop32x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-kirkwood-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-loongson-2f-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-mx5-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-orion5x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-s390x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-sparc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-versatile-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-vexpress-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nfs-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-extra-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-extra-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-extra-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-extra-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-extra-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-iop32x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-kirkwood-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-loongson-2f-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-orion5x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-s390x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-sparc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-versatile-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-vexpress-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-pcmcia-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-pcmcia-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-pcmcia-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-pcmcia-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-pcmcia-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-iop32x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-kirkwood-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-loongson-2f-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-mx5-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-orion5x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-versatile-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-vexpress-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-iop32x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-kirkwood-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-loongson-2f-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-mx5-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-orion5x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-versatile-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-vexpress-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-3.2.0-4-mx5-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-3.2.0-4-vexpress-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"parport-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"parport-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"parport-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"parport-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.2.0-4-iop32x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.2.0-4-mx5-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.2.0-4-sparc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-storage-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-storage-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-storage-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-storage-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-storage-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"plip-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"plip-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"plip-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"plip-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"plip-modules-3.2.0-4-sparc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-4kc-malta-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-iop32x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-kirkwood-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-loongson-2f-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-orion5x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-sparc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-versatile-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qnx4-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qnx4-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qnx4-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-4kc-malta-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-iop32x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-kirkwood-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-loongson-2f-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-mx5-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-orion5x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-sparc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-versatile-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rtc-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-4kc-malta-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-iop32x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-kirkwood-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-loongson-2f-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-mx5-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-orion5x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-sparc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-versatile-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.2.0-4-sparc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.2.0-4-versatile-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-iop32x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-kirkwood-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-mx5-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-orion5x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-s390x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-sparc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-versatile-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-vexpress-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-extra-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-extra-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-extra-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-extra-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-extra-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.2.0-4-s390x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.2.0-4-sparc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sn-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-4kc-malta-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-iop32x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-kirkwood-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-loongson-2f-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-mx5-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-orion5x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-sparc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-versatile-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-vexpress-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-4kc-malta-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-iop32x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-kirkwood-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-loongson-2f-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-mx5-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-orion5x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-sparc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-versatile-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-vexpress-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ufs-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ufs-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ufs-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ufs-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ufs-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ufs-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-kirkwood-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-mx5-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-vexpress-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-4kc-malta-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-iop32x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-kirkwood-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-loongson-2f-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-orion5x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-sparc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-versatile-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-vexpress-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-iop32x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-kirkwood-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-orion5x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-versatile-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-4kc-malta-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-iop32x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-kirkwood-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-loongson-2f-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-mx5-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-orion5x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-sparc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-versatile-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-vexpress-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-4kc-malta-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-loongson-2f-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-s390x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-sparc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-versatile-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-linux-system-3.2.0-4-686-pae", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-linux-system-3.2.0-4-amd64", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-4kc-malta-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-loongson-2f-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-powerpc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-s390x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-sparc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-486-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-4kc-malta-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-686-pae-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-amd64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-iop32x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-itanium-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-loongson-2f-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-orion5x-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-powerpc-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-sparc64-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-versatile-di", ver:"3.2.73-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"acpi-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"acpi-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"acpi-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-3.16.0-4-4kc-malta-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-3.16.0-4-loongson-2e-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-3.16.0-4-loongson-2f-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-3.16.0-4-loongson-3-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-3.16.0-4-octeon-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.16.0-4-arm64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.16.0-4-armmp-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.16.0-4-loongson-2e-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.16.0-4-loongson-2f-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.16.0-4-loongson-3-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.16.0-4-powerpc64le-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.16.0-4-4kc-malta-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.16.0-4-arm64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.16.0-4-armmp-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.16.0-4-kirkwood-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.16.0-4-loongson-2e-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.16.0-4-loongson-2f-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.16.0-4-loongson-3-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.16.0-4-octeon-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.16.0-4-orion5x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.16.0-4-powerpc64le-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.16.0-4-r4k-ip22-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.16.0-4-r5k-ip32-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.16.0-4-versatile-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.16.0-4-4kc-malta-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.16.0-4-arm64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.16.0-4-kirkwood-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.16.0-4-loongson-2e-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.16.0-4-loongson-2f-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.16.0-4-loongson-3-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.16.0-4-octeon-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.16.0-4-orion5x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.16.0-4-powerpc64le-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.16.0-4-versatile-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.16.0-4-arm64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.16.0-4-armmp-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.16.0-4-kirkwood-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.16.0-4-orion5x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.16.0-4-powerpc64le-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.16.0-4-s390x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.16.0-4-versatile-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.16.0-4-4kc-malta-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.16.0-4-arm64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.16.0-4-armmp-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.16.0-4-kirkwood-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.16.0-4-loongson-2e-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.16.0-4-loongson-2f-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.16.0-4-loongson-3-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.16.0-4-octeon-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.16.0-4-orion5x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.16.0-4-powerpc64le-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.16.0-4-r4k-ip22-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.16.0-4-r5k-ip32-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.16.0-4-versatile-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.16.0-4-4kc-malta-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.16.0-4-arm64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.16.0-4-armmp-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.16.0-4-kirkwood-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.16.0-4-loongson-2e-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.16.0-4-loongson-2f-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.16.0-4-loongson-3-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.16.0-4-octeon-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.16.0-4-orion5x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.16.0-4-powerpc64le-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.16.0-4-r4k-ip22-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.16.0-4-r5k-ip32-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.16.0-4-s390x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.16.0-4-versatile-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.16.0-4-4kc-malta-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.16.0-4-arm64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.16.0-4-armmp-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.16.0-4-kirkwood-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.16.0-4-loongson-2e-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.16.0-4-loongson-2f-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.16.0-4-loongson-3-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.16.0-4-octeon-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.16.0-4-orion5x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.16.0-4-powerpc64le-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.16.0-4-r4k-ip22-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.16.0-4-r5k-ip32-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.16.0-4-s390x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.16.0-4-versatile-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dasd-extra-modules-3.16.0-4-s390x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dasd-modules-3.16.0-4-s390x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-modules-3.16.0-4-arm64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.16.0-4-4kc-malta-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.16.0-4-arm64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.16.0-4-armmp-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.16.0-4-kirkwood-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.16.0-4-loongson-2e-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.16.0-4-loongson-2f-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.16.0-4-loongson-3-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.16.0-4-octeon-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.16.0-4-orion5x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.16.0-4-powerpc64le-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.16.0-4-arm64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.16.0-4-armmp-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.16.0-4-kirkwood-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.16.0-4-orion5x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.16.0-4-powerpc64le-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.16.0-4-s390x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.16.0-4-versatile-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fancontrol-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fancontrol-modules-3.16.0-4-powerpc64le-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.16.0-4-4kc-malta-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.16.0-4-arm64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.16.0-4-armmp-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.16.0-4-kirkwood-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.16.0-4-loongson-2e-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.16.0-4-loongson-2f-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.16.0-4-loongson-3-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.16.0-4-octeon-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.16.0-4-orion5x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.16.0-4-powerpc64le-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.16.0-4-s390x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.16.0-4-versatile-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-3.16.0-4-armmp-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-3.16.0-4-kirkwood-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-3.16.0-4-loongson-2e-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-3.16.0-4-loongson-2f-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-3.16.0-4-loongson-3-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-3.16.0-4-powerpc64le-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.16.0-4-4kc-malta-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.16.0-4-arm64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.16.0-4-armmp-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.16.0-4-kirkwood-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.16.0-4-loongson-2e-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.16.0-4-loongson-2f-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.16.0-4-loongson-3-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.16.0-4-octeon-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.16.0-4-orion5x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.16.0-4-powerpc64le-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.16.0-4-r4k-ip22-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.16.0-4-r5k-ip32-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.16.0-4-s390x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.16.0-4-versatile-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hfs-modules-3.16.0-4-4kc-malta-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hfs-modules-3.16.0-4-loongson-2e-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hfs-modules-3.16.0-4-loongson-2f-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hfs-modules-3.16.0-4-loongson-3-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hfs-modules-3.16.0-4-octeon-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hfs-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hfs-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hfs-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hyperv-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hyperv-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hyperv-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hypervisor-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hypervisor-modules-3.16.0-4-powerpc64le-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-3.16.0-4-4kc-malta-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.16.0-4-4kc-malta-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.16.0-4-arm64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.16.0-4-armmp-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.16.0-4-kirkwood-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.16.0-4-loongson-2e-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.16.0-4-loongson-2f-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.16.0-4-loongson-3-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.16.0-4-octeon-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.16.0-4-powerpc64le-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-3.16.0-4-orion5x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.16.0-4-4kc-malta-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.16.0-4-arm64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.16.0-4-armmp-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.16.0-4-kirkwood-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.16.0-4-loongson-2e-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.16.0-4-loongson-2f-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.16.0-4-loongson-3-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.16.0-4-octeon-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.16.0-4-orion5x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.16.0-4-powerpc64le-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.16.0-4-r4k-ip22-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.16.0-4-r5k-ip32-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.16.0-4-versatile-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jffs2-modules-3.16.0-4-orion5x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.16.0-4-4kc-malta-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.16.0-4-arm64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.16.0-4-armmp-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.16.0-4-kirkwood-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.16.0-4-loongson-2e-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.16.0-4-loongson-2f-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.16.0-4-loongson-3-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.16.0-4-octeon-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.16.0-4-orion5x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.16.0-4-powerpc64le-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.16.0-4-r4k-ip22-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.16.0-4-r5k-ip32-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.16.0-4-4kc-malta-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.16.0-4-arm64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.16.0-4-armmp-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.16.0-4-kirkwood-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.16.0-4-loongson-2e-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.16.0-4-loongson-2f-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.16.0-4-loongson-3-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.16.0-4-octeon-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.16.0-4-orion5x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.16.0-4-powerpc64le-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.16.0-4-r4k-ip22-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.16.0-4-r5k-ip32-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.16.0-4-s390x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.16.0-4-versatile-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"leds-modules-3.16.0-4-kirkwood-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-4.8-arm", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-4.8-s390", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-4.8-x86", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-3.16", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-4kc-malta", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-586", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-5kc-malta", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-686-pae", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-all", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-all-amd64", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-all-arm64", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-all-armel", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-all-armhf", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-all-i386", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-all-mips", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-all-mipsel", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-all-powerpc", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-all-ppc64el", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-all-s390x", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-amd64", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-arm64", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-armmp", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-armmp-lpae", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-common", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-ixp4xx", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-kirkwood", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-loongson-2e", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-loongson-2f", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-loongson-3", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-octeon", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-orion5x", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-powerpc", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-powerpc-smp", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-powerpc64", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-powerpc64le", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-r4k-ip22", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-r5k-ip32", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-s390x", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-sb1-bcm91250a", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-versatile", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-4kc-malta", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-586", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-5kc-malta", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-686-pae", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-686-pae-dbg", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-amd64", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-amd64-dbg", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-arm64", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-arm64-dbg", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-armmp", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-armmp-lpae", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-ixp4xx", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-kirkwood", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-loongson-2e", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-loongson-2f", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-loongson-3", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-octeon", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-orion5x", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-powerpc", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-powerpc-smp", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-powerpc64", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-powerpc64le", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-r4k-ip22", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-r5k-ip32", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-s390x", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-s390x-dbg", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-sb1-bcm91250a", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-versatile", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-libc-dev", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-manual-3.16", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-3.16", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-support-3.16.0-4", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.16.0-4-4kc-malta-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.16.0-4-arm64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.16.0-4-armmp-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.16.0-4-kirkwood-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.16.0-4-loongson-2e-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.16.0-4-loongson-2f-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.16.0-4-loongson-3-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.16.0-4-octeon-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.16.0-4-orion5x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.16.0-4-powerpc64le-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.16.0-4-r4k-ip22-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.16.0-4-r5k-ip32-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.16.0-4-versatile-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.16.0-4-4kc-malta-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.16.0-4-arm64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.16.0-4-armmp-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.16.0-4-kirkwood-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.16.0-4-loongson-2e-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.16.0-4-loongson-2f-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.16.0-4-loongson-3-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.16.0-4-octeon-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.16.0-4-orion5x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.16.0-4-powerpc64le-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.16.0-4-r4k-ip22-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.16.0-4-r5k-ip32-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.16.0-4-s390x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.16.0-4-versatile-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-3.16.0-4-4kc-malta-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-3.16.0-4-kirkwood-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-3.16.0-4-loongson-2e-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-3.16.0-4-loongson-2f-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-3.16.0-4-loongson-3-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-3.16.0-4-octeon-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-3.16.0-4-orion5x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-3.16.0-4-4kc-malta-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-3.16.0-4-4kc-malta-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-3.16.0-4-arm64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-3.16.0-4-armmp-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-3.16.0-4-kirkwood-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-3.16.0-4-4kc-malta-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-3.16.0-4-kirkwood-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-3.16.0-4-powerpc64le-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-modules-3.16.0-4-armmp-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.16.0-4-4kc-malta-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.16.0-4-arm64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.16.0-4-armmp-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.16.0-4-kirkwood-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.16.0-4-loongson-2e-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.16.0-4-loongson-2f-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.16.0-4-loongson-3-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.16.0-4-octeon-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.16.0-4-orion5x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.16.0-4-powerpc64le-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.16.0-4-r4k-ip22-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.16.0-4-r5k-ip32-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.16.0-4-s390x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.16.0-4-versatile-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.16.0-4-4kc-malta-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.16.0-4-arm64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.16.0-4-armmp-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.16.0-4-kirkwood-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.16.0-4-loongson-2e-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.16.0-4-loongson-2f-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.16.0-4-loongson-3-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.16.0-4-octeon-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.16.0-4-orion5x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.16.0-4-powerpc64le-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.16.0-4-r4k-ip22-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.16.0-4-r5k-ip32-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.16.0-4-s390x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.16.0-4-versatile-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nfs-modules-3.16.0-4-loongson-2e-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nfs-modules-3.16.0-4-loongson-2f-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nfs-modules-3.16.0-4-loongson-3-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.16.0-4-4kc-malta-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.16.0-4-arm64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.16.0-4-armmp-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.16.0-4-kirkwood-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.16.0-4-loongson-2e-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.16.0-4-loongson-2f-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.16.0-4-loongson-3-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.16.0-4-octeon-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.16.0-4-orion5x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.16.0-4-powerpc64le-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.16.0-4-s390x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.16.0-4-versatile-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-pcmcia-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-pcmcia-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-pcmcia-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-pcmcia-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-pcmcia-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.16.0-4-4kc-malta-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.16.0-4-arm64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.16.0-4-armmp-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.16.0-4-kirkwood-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.16.0-4-loongson-2e-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.16.0-4-loongson-2f-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.16.0-4-loongson-3-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.16.0-4-octeon-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.16.0-4-orion5x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.16.0-4-powerpc64le-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.16.0-4-r4k-ip22-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.16.0-4-r5k-ip32-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.16.0-4-versatile-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.16.0-4-4kc-malta-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.16.0-4-arm64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.16.0-4-armmp-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.16.0-4-kirkwood-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.16.0-4-loongson-2e-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.16.0-4-loongson-2f-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.16.0-4-loongson-3-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.16.0-4-octeon-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.16.0-4-orion5x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.16.0-4-versatile-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-3.16.0-4-4kc-malta-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-3.16.0-4-arm64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-3.16.0-4-armmp-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-3.16.0-4-loongson-2e-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-3.16.0-4-loongson-2f-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-3.16.0-4-loongson-3-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-3.16.0-4-octeon-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-3.16.0-4-4kc-malta-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-3.16.0-4-loongson-2e-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-3.16.0-4-loongson-2f-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-3.16.0-4-loongson-3-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-3.16.0-4-octeon-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.16.0-4-4kc-malta-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.16.0-4-armmp-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.16.0-4-loongson-2e-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.16.0-4-loongson-2f-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.16.0-4-loongson-3-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.16.0-4-octeon-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-storage-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-storage-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-storage-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-storage-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-storage-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.16.0-4-4kc-malta-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.16.0-4-arm64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.16.0-4-armmp-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.16.0-4-kirkwood-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.16.0-4-loongson-2e-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.16.0-4-loongson-2f-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.16.0-4-loongson-3-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.16.0-4-octeon-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.16.0-4-orion5x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.16.0-4-powerpc64le-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.16.0-4-versatile-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rtc-modules-3.16.0-4-octeon-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rtc-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.16.0-4-4kc-malta-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.16.0-4-arm64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.16.0-4-armmp-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.16.0-4-kirkwood-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.16.0-4-loongson-2e-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.16.0-4-loongson-2f-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.16.0-4-loongson-3-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.16.0-4-octeon-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.16.0-4-orion5x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.16.0-4-powerpc64le-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.16.0-4-versatile-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.16.0-4-4kc-malta-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.16.0-4-loongson-2e-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.16.0-4-loongson-2f-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.16.0-4-loongson-3-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.16.0-4-octeon-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.16.0-4-powerpc64le-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.16.0-4-versatile-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.16.0-4-4kc-malta-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.16.0-4-arm64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.16.0-4-armmp-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.16.0-4-kirkwood-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.16.0-4-loongson-2e-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.16.0-4-loongson-2f-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.16.0-4-loongson-3-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.16.0-4-octeon-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.16.0-4-orion5x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.16.0-4-powerpc64le-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.16.0-4-s390x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.16.0-4-versatile-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-extra-modules-3.16.0-4-4kc-malta-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-extra-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-extra-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-extra-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-extra-modules-3.16.0-4-loongson-2e-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-extra-modules-3.16.0-4-loongson-2f-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-extra-modules-3.16.0-4-loongson-3-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-extra-modules-3.16.0-4-octeon-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-extra-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-extra-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-extra-modules-3.16.0-4-powerpc64le-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-extra-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.16.0-4-4kc-malta-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.16.0-4-arm64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.16.0-4-armmp-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.16.0-4-loongson-2e-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.16.0-4-loongson-2f-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.16.0-4-loongson-3-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.16.0-4-octeon-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.16.0-4-powerpc64le-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.16.0-4-s390x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-3.16.0-4-powerpc64le-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-3.16.0-4-4kc-malta-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-3.16.0-4-loongson-2e-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-3.16.0-4-loongson-2f-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-3.16.0-4-loongson-3-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-3.16.0-4-octeon-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-3.16.0-4-loongson-2e-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-3.16.0-4-loongson-2f-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-3.16.0-4-loongson-3-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.16.0-4-4kc-malta-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.16.0-4-arm64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.16.0-4-armmp-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.16.0-4-kirkwood-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.16.0-4-loongson-2e-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.16.0-4-loongson-2f-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.16.0-4-loongson-3-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.16.0-4-octeon-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.16.0-4-orion5x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.16.0-4-powerpc64le-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.16.0-4-r4k-ip22-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.16.0-4-r5k-ip32-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.16.0-4-versatile-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.16.0-4-4kc-malta-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.16.0-4-arm64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.16.0-4-armmp-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.16.0-4-kirkwood-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.16.0-4-loongson-2e-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.16.0-4-loongson-2f-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.16.0-4-loongson-3-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.16.0-4-octeon-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.16.0-4-orion5x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.16.0-4-powerpc64le-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.16.0-4-r4k-ip22-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.16.0-4-r5k-ip32-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.16.0-4-versatile-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.16.0-4-arm64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.16.0-4-armmp-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.16.0-4-kirkwood-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.16.0-4-powerpc64le-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.16.0-4-4kc-malta-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.16.0-4-arm64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.16.0-4-armmp-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.16.0-4-kirkwood-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.16.0-4-loongson-2e-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.16.0-4-loongson-2f-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.16.0-4-loongson-3-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.16.0-4-octeon-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.16.0-4-orion5x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.16.0-4-powerpc64le-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.16.0-4-versatile-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.16.0-4-4kc-malta-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.16.0-4-kirkwood-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.16.0-4-loongson-2e-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.16.0-4-loongson-2f-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.16.0-4-loongson-3-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.16.0-4-octeon-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.16.0-4-orion5x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.16.0-4-powerpc64le-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.16.0-4-versatile-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.16.0-4-4kc-malta-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.16.0-4-arm64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.16.0-4-armmp-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.16.0-4-kirkwood-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.16.0-4-loongson-2e-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.16.0-4-loongson-2f-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.16.0-4-loongson-3-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.16.0-4-octeon-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.16.0-4-orion5x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.16.0-4-powerpc64le-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.16.0-4-versatile-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.16.0-4-4kc-malta-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.16.0-4-arm64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.16.0-4-armmp-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.16.0-4-loongson-2e-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.16.0-4-loongson-2f-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.16.0-4-loongson-3-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.16.0-4-octeon-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.16.0-4-powerpc64le-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.16.0-4-s390x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.16.0-4-versatile-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-linux-system-3.16.0-4-amd64", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.16.0-4-4kc-malta-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.16.0-4-586-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.16.0-4-686-pae-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.16.0-4-amd64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.16.0-4-arm64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.16.0-4-loongson-2e-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.16.0-4-loongson-2f-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.16.0-4-loongson-3-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.16.0-4-octeon-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.16.0-4-powerpc64-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.16.0-4-powerpc64le-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.16.0-4-r4k-ip22-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.16.0-4-r5k-ip32-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.16.0-4-s390x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.16.0-4-4kc-malta-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.16.0-4-armmp-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.16.0-4-loongson-2e-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.16.0-4-loongson-2f-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.16.0-4-loongson-3-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.16.0-4-octeon-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.16.0-4-orion5x-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.16.0-4-powerpc-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.16.0-4-r4k-ip22-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.16.0-4-r5k-ip32-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.16.0-4-versatile-di", ver:"3.16.7-ckt20-1+deb8u4", rls:"DEB8"))) {
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
