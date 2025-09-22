# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123914");
  script_cve_id("CVE-2012-2136");
  script_tag(name:"creation_date", value:"2015-10-06 11:10:14 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2012-0690)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-0690");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-0690.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-308.8.1.el5, oracleasm-2.6.18-308.8.1.el5' package(s) announced via the ELSA-2012-0690 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.18-308.8.1.el5]
- [net] sock: validate data_len before allocating skb in sock_alloc_send_pskb() (Jason Wang) [816290 816106] {CVE-2012-2136}
- [net] tg3: Fix VLAN tagging assignments (John Feeney) [817691 797011]
- [net] ixgbe: do not stop stripping VLAN tags in promiscuous mode (Andy Gospodarek) [809791 804800]
- [s390] zcrypt: Fix parameter checking for ZSECSENDCPRB ioctl (Hendrik Brueckner) [810123 808489]
- [x86] unwind information fix for the vsyscall DSO (Prarit Bhargava) [807930 805799]

[2.6.18-308.7.1.el5]
- [fs] epoll: Don't limit non-nested epoll paths (Jason Baron) [809380 804778]

[2.6.18-308.6.1.el5]
- [scsi] fc class: fix scanning when devs are offline (Mike Christie) [816684 799530]
- [md] dm-multipath: delay retry of bypassed pg (Mike Christie) [816684 799530]
- [net] bonding: properly unset current_arp_slave on slave link up (Veaceslav Falico) [811927 800575]
- [net] bonding: remove {master,vlan}_ip and query devices instead (Andy Gospodarek) [810321 772216]

[2.6.18-308.5.1.el5]
- [scsi] skip sense logging for some ATA PASS-THROUGH cdbs (David Milburn) [807265 788777]");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-308.8.1.el5, oracleasm-2.6.18-308.8.1.el5' package(s) on Oracle Linux 5.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~308.8.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~308.8.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~308.8.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~308.8.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~308.8.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~308.8.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~308.8.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~308.8.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~308.8.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~308.8.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-308.8.1.el5", rpm:"ocfs2-2.6.18-308.8.1.el5~1.4.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-308.8.1.el5PAE", rpm:"ocfs2-2.6.18-308.8.1.el5PAE~1.4.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-308.8.1.el5debug", rpm:"ocfs2-2.6.18-308.8.1.el5debug~1.4.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-308.8.1.el5xen", rpm:"ocfs2-2.6.18-308.8.1.el5xen~1.4.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-308.8.1.el5", rpm:"oracleasm-2.6.18-308.8.1.el5~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-308.8.1.el5PAE", rpm:"oracleasm-2.6.18-308.8.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-308.8.1.el5debug", rpm:"oracleasm-2.6.18-308.8.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-308.8.1.el5xen", rpm:"oracleasm-2.6.18-308.8.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5"))) {
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
