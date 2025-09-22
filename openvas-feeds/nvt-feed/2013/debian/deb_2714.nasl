# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702714");
  script_cve_id("CVE-2013-2171");
  script_tag(name:"creation_date", value:"2013-06-24 22:00:00 +0000 (Mon, 24 Jun 2013)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2714-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-2714-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/DSA-2714-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2714");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kfreebsd-9' package(s) announced via the DSA-2714-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Konstantin Belousov and Alan Cox discovered that insufficient permission checks in the memory management of the FreeBSD kernel could lead to privilege escalation.

For the stable distribution (wheezy), this problem has been fixed in version 9.0-10+deb70.2.

For the unstable distribution (sid), this problem has been fixed in version 9.0-12.

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

  if(!isnull(res = isdpkgvuln(pkg:"acpi-modules-9.0-2-486-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"acpi-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-modules-9.0-2-486-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-9.0-2-486-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-9.0-2-486-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext2-modules-9.0-2-486-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext2-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-9.0-2-486-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"floppy-modules-9.0-2-486-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"floppy-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-9.0-2-486-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-9.0-2-486-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-9.0-2-486-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-9.0-2-486-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-9.0-2-amd64-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-headers-9-486", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-headers-9-686", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-headers-9-686-smp", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-headers-9-amd64", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-headers-9-malta", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-headers-9-xen", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-headers-9.0-2", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-headers-9.0-2-486", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-headers-9.0-2-686", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-headers-9.0-2-686-smp", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-headers-9.0-2-amd64", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-headers-9.0-2-malta", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-headers-9.0-2-xen", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-image-9-486", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-image-9-686", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-image-9-686-smp", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-image-9-amd64", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-image-9-malta", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-image-9-xen", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-image-9.0-2-486", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-image-9.0-2-686", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-image-9.0-2-686-smp", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-image-9.0-2-amd64", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-image-9.0-2-malta", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-image-9.0-2-xen", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfreebsd-source-9.0", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-9.0-2-486-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-9.0-2-486-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-9.0-2-486-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-9.0-2-486-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nfs-modules-9.0-2-486-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nfs-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-9.0-2-486-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-9.0-2-486-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-9.0-2-486-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nls-core-modules-9.0-2-486-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nls-core-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-9.0-2-486-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nullfs-modules-9.0-2-486-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nullfs-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"parport-modules-9.0-2-486-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"parport-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"plip-modules-9.0-2-486-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"plip-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-9.0-2-486-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-9.0-2-486-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-9.0-2-486-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-9.0-2-486-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-extra-modules-9.0-2-486-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-extra-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-9.0-2-486-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-9.0-2-486-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-9.0-2-486-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-9.0-2-486-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zfs-modules-9.0-2-486-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zfs-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-9.0-2-486-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-9.0-2-amd64-di", ver:"9.0-10+deb70.2", rls:"DEB7"))) {
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
