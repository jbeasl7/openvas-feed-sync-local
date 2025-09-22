# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703070");
  script_cve_id("CVE-2014-3711", "CVE-2014-3952", "CVE-2014-3953", "CVE-2014-8476");
  script_tag(name:"creation_date", value:"2014-11-06 23:00:00 +0000 (Thu, 06 Nov 2014)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-3070-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3070-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/DSA-3070-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3070");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kfreebsd-9' package(s) announced via the DSA-3070-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the FreeBSD kernel that may lead to a denial of service or information disclosure.

CVE-2014-3711

Denial of service through memory leak in sandboxed namei lookups.

CVE-2014-3952

Kernel memory disclosure in sockbuf control messages.

CVE-2014-3953

Kernel memory disclosure in SCTP. This update disables SCTP, since the userspace tools shipped in Wheezy didn't support SCTP anyway.

CVE-2014-8476

Kernel stack disclosure in setlogin() and getlogin().

For the stable distribution (wheezy), these problems have been fixed in version 9.0-10+deb70.8.

We recommend that you upgrade your kfreebsd-9 packages.");

  script_tag(name:"affected", value:"'kfreebsd-9' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"acpi-modules-9.0-2-486-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"acpi-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-modules-9.0-2-486-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-9.0-2-486-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-9.0-2-486-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext2-modules-9.0-2-486-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext2-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-9.0-2-486-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"floppy-modules-9.0-2-486-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"floppy-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-9.0-2-486-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-9.0-2-486-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-9.0-2-486-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-9.0-2-486-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-9.0-2-amd64-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-headers-9-486", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-headers-9-686", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-headers-9-686-smp", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-headers-9-amd64", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-headers-9-malta", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-headers-9-xen", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-headers-9.0-2", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-headers-9.0-2-486", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-headers-9.0-2-686", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-headers-9.0-2-686-smp", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-headers-9.0-2-amd64", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-headers-9.0-2-malta", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-headers-9.0-2-xen", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-image-9-486", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-image-9-686", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-image-9-686-smp", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-image-9-amd64", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-image-9-malta", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-image-9-xen", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-image-9.0-2-486", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-image-9.0-2-686", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-image-9.0-2-686-smp", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-image-9.0-2-amd64", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-image-9.0-2-malta", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-image-9.0-2-xen", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-source-9.0", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-9.0-2-486-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-9.0-2-486-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-9.0-2-486-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-9.0-2-486-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nfs-modules-9.0-2-486-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nfs-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-9.0-2-486-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-9.0-2-486-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-9.0-2-486-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nls-core-modules-9.0-2-486-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nls-core-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-9.0-2-486-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nullfs-modules-9.0-2-486-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nullfs-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"parport-modules-9.0-2-486-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"parport-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"plip-modules-9.0-2-486-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"plip-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-9.0-2-486-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-9.0-2-486-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-9.0-2-486-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-9.0-2-486-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-extra-modules-9.0-2-486-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-extra-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-9.0-2-486-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-9.0-2-486-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-9.0-2-486-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-9.0-2-486-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zfs-modules-9.0-2-486-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zfs-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-9.0-2-486-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.8", rls:"DEB7"))) {
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
