# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.3249.1");
  script_cve_id("CVE-2014-0038", "CVE-2017-1000405", "CVE-2017-12193", "CVE-2017-15102", "CVE-2017-16525", "CVE-2017-16527", "CVE-2017-16529", "CVE-2017-16531", "CVE-2017-16535", "CVE-2017-16536", "CVE-2017-16537", "CVE-2017-16649", "CVE-2017-16650", "CVE-2017-16939");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-08 15:57:07 +0000 (Fri, 08 Dec 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:3249-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:3249-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20173249-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1043652");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047626");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066192");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066471");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066472");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066573");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066606");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066618");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066625");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066650");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066671");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066700");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066705");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1067085");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1067086");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1067997");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1069496");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1069702");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1069708");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1070307");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1070781");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/860993");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-December/003486.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2017:3249-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 kernel was updated to 3.12.61 to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2017-16939: The XFRM dump policy implementation in net/xfrm/xfrm_user.c in the Linux kernel allowed local users to gain privileges or cause a denial of service (use-after-free) via a crafted SO_RCVBUF setsockopt system call in conjunction with XFRM_MSG_GETPOLICY Netlink messages (bnc#1069702 1069708).
- CVE-2017-1000405: The Linux Kernel had a problematic use of pmd_mkdirty() in the touch_pmd() function inside the THP implementation. touch_pmd() could be reached by get_user_pages(). In such case, the pmd would become dirty. This scenario breaks the new can_follow_write_pmd()'s logic - pmd could become dirty without going through a COW cycle. This bug was not as severe as the original 'Dirty cow' because an ext4 file (or any other regular file) could not be mapped using THP. Nevertheless, it did allow us to overwrite read-only huge pages. For example, the zero huge page and sealed shmem files could be overwritten (since their mapping could be populated using THP). Note that after the first write page-fault to the zero page, it will be replaced with a new fresh (and zeroed) thp (bnc#1069496 1070307).
- CVE-2017-16649: The usbnet_generic_cdc_bind function in drivers/net/usb/cdc_ether.c in the Linux kernel allowed local users to cause a denial of service (divide-by-zero error and system crash) or possibly have unspecified other impact via a crafted USB device (bnc#1067085).
- CVE-2014-0038: The compat_sys_recvmmsg function in net/compat.c in the Linux kernel, when CONFIG_X86_X32 is enabled, allowed local users to gain privileges via a recvmmsg system call with a crafted timeout pointer parameter (bnc#860993).
- CVE-2017-16650: The qmi_wwan_bind function in drivers/net/usb/qmi_wwan.c in the Linux kernel allowed local users to cause a denial of service (divide-by-zero error and system crash) or possibly have unspecified other impact via a crafted USB device (bnc#1067086).
- CVE-2017-16535: The usb_get_bos_descriptor function in drivers/usb/core/config.c in the Linux kernel allowed local users to cause a denial of service (out-of-bounds read and system crash) or possibly have unspecified other impact via a crafted USB device (bnc#1066700).
- CVE-2017-15102: The tower_probe function in drivers/usb/misc/legousbtower.c in the Linux kernel allowed local users (who are physically proximate for inserting a crafted USB device) to gain privileges by leveraging a write-what-where condition that occurs after a race condition and a NULL pointer dereference (bnc#1066705).
- CVE-2017-16531: drivers/usb/core/config.c in the Linux kernel allowed local users to cause a denial of service (out-of-bounds read and system crash) or possibly have unspecified other impact via a crafted USB device, related to the USB_DT_INTERFACE_ASSOCIATION descriptor ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.12.61~52.106.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debuginfo", rpm:"kernel-ec2-debuginfo~3.12.61~52.106.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debugsource", rpm:"kernel-ec2-debugsource~3.12.61~52.106.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.12.61~52.106.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra", rpm:"kernel-ec2-extra~3.12.61~52.106.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra-debuginfo", rpm:"kernel-ec2-extra-debuginfo~3.12.61~52.106.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.12.61~52.106.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.12.61~52.106.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.12.61~52.106.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.12.61~52.106.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.12.61~52.106.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~3.12.61~52.106.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.12.61~52.106.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.12.61~52.106.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.12.61~52.106.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.12.61~52.106.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.12.61~52.106.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_61-52_106-default", rpm:"kgraft-patch-3_12_61-52_106-default~1~5.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_61-52_106-xen", rpm:"kgraft-patch-3_12_61-52_106-xen~1~5.1", rls:"SLES12.0"))) {
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
