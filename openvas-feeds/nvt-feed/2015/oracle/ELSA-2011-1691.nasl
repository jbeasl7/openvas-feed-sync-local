# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122032");
  script_cve_id("CVE-2011-1675", "CVE-2011-1677");
  script_tag(name:"creation_date", value:"2015-10-06 11:11:58 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2011-1691)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-1691");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-1691.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'util-linux-ng' package(s) announced via the ELSA-2011-1691 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.17.2-12.4]
- fix CVE-2011-1675 - mount fails to anticipate RLIMIT_FSIZE
- fix CVE-2011-1677 - umount may fail to remove /etc/mtab~ lock file

[2.17.2-12.3]
- fix fatal typos in patch for #723546

[2.17.2-12.2]
- rename /etc/hushlogin to /etc/hushlogins (#696731)

[2.17.2-12.1]
- fix #723546 - Defects revealed by Coverity scan
- fix #723352 - cfdisk cannot read default installer partitioning
- fix #712158 - uid/gid overflow in ipcs
- fix #696959 - wipefs(8) reject partitioned devices
- fix #694648 - document blank line at head of fstab
- fix #684203 - umount fails on inconsistent fstab
- fix #679831 --lines does not work
- fix #679741 - canonicalize swap device
- fix #692119 - include fstrim tool
- fix #675999 - blkid crashes on a server with more than 128 storage devices
- fix #696731 - display failed login attempts
- fix #726092 - Pass host name from agetty to login
- fix #716995 - Remove Deprecation Statement in /etc/udev/rules.d/60-raw.rules
- fix #712808 - uuidd should depend on chkconfig
- fix #723638 - Backport upstream extensions for lsblk (RHEL6.2)");

  script_tag(name:"affected", value:"'util-linux-ng' package(s) on Oracle Linux 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"libblkid", rpm:"libblkid~2.17.2~12.4.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblkid-devel", rpm:"libblkid-devel~2.17.2~12.4.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuuid", rpm:"libuuid~2.17.2~12.4.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuuid-devel", rpm:"libuuid-devel~2.17.2~12.4.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"util-linux-ng", rpm:"util-linux-ng~2.17.2~12.4.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uuidd", rpm:"uuidd~2.17.2~12.4.el6", rls:"OracleLinux6"))) {
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
