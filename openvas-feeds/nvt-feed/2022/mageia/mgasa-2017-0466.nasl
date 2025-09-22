# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0466");
  script_cve_id("CVE-2017-0786", "CVE-2017-12190", "CVE-2017-12193", "CVE-2017-13080", "CVE-2017-15115", "CVE-2017-15265", "CVE-2017-15299", "CVE-2017-16939", "CVE-2017-16994", "CVE-2017-7518");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-08 15:57:07 +0000 (Fri, 08 Dec 2017)");

  script_name("Mageia: Security Advisory (MGASA-2017-0466)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0466");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0466.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22179");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.100");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.101");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.102");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.103");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.104");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.105");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.93");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.94");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.95");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.96");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.97");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.98");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.99");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-tmb' package(s) announced via the MGASA-2017-0466 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-tmb update is based on upstream 4.4.105 and fixes at least the
following security issues:

A security flaw was discovered in nl80211_set_rekey_data() function in the
Linux kernel since v3.1-rc1 through v4.13. This function does not check
whether the required attributes are present in a netlink request. This
request can be issued by a user with CAP_NET_ADMIN privilege and may result
in NULL dereference and a system crash (CVE-2017-12153).

Linux kernel built with the KVM visualization support (CONFIG_KVM), with
nested visualization (nVMX) feature enabled (nested=1), is vulnerable to a
crash due to disabled external interrupts. As L2 guest could acce s (r/w)
hardware CR8 register of the host(L0). In a nested visualization setup,
L2 guest user could use this flaw to potentially crash the host(L0)
resulting in DoS (CVE-2017-12154).

The tcp_disconnect function in net/ipv4/tcp.c in the Linux kernel before
4.12 allows local users to cause a denial of service (__tcp_select_window
divide-by-zero error and system crash) by triggering a disconnect within a
certain tcp_recvmsg code path (CVE-2017-14106).

The atyfb_ioctl function in drivers/video/fbdev/aty/atyfb_base.c in the
Linux kernel through 4.12.10 does not initialize a certain data structure,
which allows local users to obtain sensitive information from kernel stack
memory by reading locations associated with padding bytes (CVE-2017-14156).

It was found that the iscsi_if_rx() function in scsi_transport_iscsi.c in
the Linux kernel since v2.6.24-rc1 through 4.13.2 allows local users to
cause a denial of service (a system panic) by making a number of certain
syscalls by leveraging incorrect length validation in the kernel code
(CVE-2017-14489).

The sg_ioctl function in drivers/scsi/sg.c in the Linux kernel before 4.13.4
allows local users to obtain sensitive information from uninitialized kernel
heap-memory locations via an SG_GET_REQUEST_TABLE ioctl call for /dev/sg0
(CVE-2017-14991).

A reachable assertion failure flaw was found in the Linux kernel built with
KVM virtualisation(CONFIG_KVM) support with Virtual Function I/O feature
(CONFIG_VFIO) enabled. This failure could occur if a malicious guest device
sent a virtual interrupt (guest IRQ) with a larger (>1024) index value
(CVE-2017-1000252).

For other upstream fixes in this update, read the referenced changelogs.");

  script_tag(name:"affected", value:"'kernel-tmb' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb", rpm:"kernel-tmb~4.4.105~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-4.4.105-1.mga5", rpm:"kernel-tmb-desktop-4.4.105-1.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-devel-4.4.105-1.mga5", rpm:"kernel-tmb-desktop-devel-4.4.105-1.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-devel-latest", rpm:"kernel-tmb-desktop-devel-latest~4.4.105~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-latest", rpm:"kernel-tmb-desktop-latest~4.4.105~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-source-4.4.105-1.mga5", rpm:"kernel-tmb-source-4.4.105-1.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-source-latest", rpm:"kernel-tmb-source-latest~4.4.105~1.mga5", rls:"MAGEIA5"))) {
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
