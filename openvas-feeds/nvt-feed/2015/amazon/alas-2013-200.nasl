# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120027");
  script_cve_id("CVE-2012-6544", "CVE-2012-6545", "CVE-2013-0914", "CVE-2013-1767", "CVE-2013-1773", "CVE-2013-1929", "CVE-2013-3222", "CVE-2013-3224", "CVE-2013-3231", "CVE-2013-3235");
  script_tag(name:"creation_date", value:"2015-09-08 11:15:37 +0000 (Tue, 08 Sep 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Amazon Linux: Security Advisory (ALAS-2013-200)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2013-200");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2013-200.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ALAS-2013-200 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Heap-based buffer overflow in the tg3_read_vpd function in drivers/net/ethernet/broadcom/tg3.c in the Linux kernel before 3.8.6 allows physically proximate attackers to cause a denial of service (system crash) or possibly execute arbitrary code via crafted firmware that specifies a long string in the Vital Product Data (VPD) data structure.

Use-after-free vulnerability in the shmem_remount_fs function in mm/shmem.c in the Linux kernel before 3.7.10 allows local users to gain privileges or cause a denial of service (system crash) by remounting a tmpfs filesystem without specifying a required mpol (aka mempolicy) mount option.

The vcc_recvmsg function in net/atm/common.c in the Linux kernel before 3.9-rc7 does not initialize a certain length variable, which allows local users to obtain sensitive information from kernel stack memory via a crafted recvmsg or recvfrom system call.

The flush_signal_handlers function in kernel/signal.c in the Linux kernel before 3.8.4 preserves the value of the sa_restorer field across an exec operation, which makes it easier for local users to bypass the ASLR protection mechanism via a crafted application containing a sigaction system call.

The llc_ui_recvmsg function in net/llc/af_llc.c in the Linux kernel before 3.9-rc7 does not initialize a certain length variable, which allows local users to obtain sensitive information from kernel stack memory via a crafted recvmsg or recvfrom system call.

net/tipc/socket.c in the Linux kernel before 3.9-rc7 does not initialize a certain data structure and a certain length variable, which allows local users to obtain sensitive information from kernel stack memory via a crafted recvmsg or recvfrom system call.

Buffer overflow in the VFAT filesystem implementation in the Linux kernel before 3.3 allows local users to gain privileges or cause a denial of service (system crash) via a VFAT write operation on a filesystem with the utf8 mount option, which is not properly handled during UTF-8 to UTF-16 conversion.

The Bluetooth RFCOMM implementation in the Linux kernel before 3.6 does not properly initialize certain structures, which allows local users to obtain sensitive information from kernel memory via a crafted application.

The Bluetooth protocol stack in the Linux kernel before 3.6 does not properly initialize certain structures, which allows local users to obtain sensitive information from kernel stack memory via a crafted application that targets the (1) L2CAP or (2) HCI implementation.

The bt_sock_recvmsg function in net/bluetooth/af_bluetooth.c in the Linux kernel before 3.9-rc7 does not properly initialize a certain length variable, which allows local users to obtain sensitive information from kernel stack memory via a crafted recvmsg or recvfrom system call.");

  script_tag(name:"affected", value:"'kernel' package(s) on Amazon Linux.");

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

if(release == "AMAZON") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.4.48~45.46.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~3.4.48~45.46.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo-common-i686", rpm:"kernel-debuginfo-common-i686~3.4.48~45.46.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo-common-x86_64", rpm:"kernel-debuginfo-common-x86_64~3.4.48~45.46.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.4.48~45.46.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.4.48~45.46.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.4.48~45.46.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.4.48~45.46.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-debuginfo", rpm:"kernel-tools-debuginfo~3.4.48~45.46.amzn1", rls:"AMAZON"))) {
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
