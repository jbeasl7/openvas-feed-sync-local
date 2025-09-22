# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.14218.1");
  script_cve_id("CVE-2017-18509", "CVE-2017-18551", "CVE-2018-12207", "CVE-2018-20976", "CVE-2019-10220", "CVE-2019-11135", "CVE-2019-14821", "CVE-2019-14835", "CVE-2019-15118", "CVE-2019-15212", "CVE-2019-15216", "CVE-2019-15217", "CVE-2019-15219", "CVE-2019-15291", "CVE-2019-15292", "CVE-2019-15505", "CVE-2019-15807", "CVE-2019-15902", "CVE-2019-15927", "CVE-2019-16232", "CVE-2019-16233", "CVE-2019-16234", "CVE-2019-16413", "CVE-2019-17052", "CVE-2019-17053", "CVE-2019-17054", "CVE-2019-17055", "CVE-2019-17133", "CVE-2019-9456");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:13 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-10 14:31:27 +0000 (Thu, 10 Oct 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:14218-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:14218-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-201914218-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101061");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113201");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117665");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131107");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1143327");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144903");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145477");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145922");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146163");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146285");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146361");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146391");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146524");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146540");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146547");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146678");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1147122");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1148938");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149376");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149522");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150025");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150112");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150452");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150457");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150465");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150599");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151347");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151350");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152779");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152782");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152786");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152789");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153158");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155671");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/802154");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/936875");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-November/006135.html");
  script_xref(name:"URL", value:"https://www.suse.com/support/kb/doc/?id=7023735");
  script_xref(name:"URL", value:"https://www.suse.com/support/kb/doc/?id=7024251");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:14218-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11-SP4 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2019-11135: Aborting an asynchronous TSX operation on Intel CPUs with
 Transactional Memory support could be used to facilitate sidechannel
 information leaks out of microarchitectural buffers, similar to the
 previously described 'Microarchitectural Data Sampling' attack.

 The Linux kernel was supplemented with the option to disable TSX operation
 altogether (requiring CPU Microcode updates on older systems) and better
 flushing of microarchitectural buffers (VERW).

 The set of options available is described in our TID at [link moved to references]

- CVE-2018-12207: Untrusted virtual machines on Intel CPUs could exploit a race
 condition in the Instruction Fetch Unit of the Intel CPU to cause a Machine
 Exception during Page Size Change, causing the CPU core to be non-functional.

 The Linux Kernel kvm hypervisor was adjusted to avoid page size changes in
 executable pages by splitting / merging huge pages into small pages as
 needed. More information can be found on [link moved to references]

- CVE-2019-16233: drivers/scsi/qla2xxx/qla_os.c did not check the
 alloc_workqueue return value, leading to a NULL pointer dereference.
 (bsc#1150457).
- CVE-2019-10220: Added sanity checks on the pathnames passed to the user
 space. (bsc#1144903).
- CVE-2019-16234: iwlwifi pcie driver did not check the alloc_workqueue return
 value, leading to a NULL pointer dereference. (bsc#1150452).
- CVE-2019-16232: Fix a potential NULL pointer dereference in the Marwell
 libertas driver (bsc#1150465).
- CVE-2019-17052: ax25_create in the AF_AX25 network module in the Linux kernel
 did not enforce CAP_NET_RAW, which meant that unprivileged users could create
 a raw socket, aka CID-0614e2b73768. (bnc#1152779)
- CVE-2019-17055: base_sock_create in the AF_ISDN network module in the Linux kernel
 did not enforce CAP_NET_RAW, which means that unprivileged users can create
 a raw socket, aka CID-b91ee4aa2a21. (bnc#1152782)
- CVE-2019-17054: atalk_create in the AF_APPLETALK network module in the Linux kernel
 did not enforce CAP_NET_RAW, which means that unprivileged users can create
 a raw socket, aka CID-6cc03e8aa36c. (bnc#1152786)
- CVE-2019-17133: cfg80211 wireless extension did not reject a long SSID IE,
 leading to a Buffer Overflow (bsc#1153158).
- CVE-2019-17053: ieee802154_create in the AF_IEEE802154 network module in the Linux kernel
 did not enforce CAP_NET_RAW, which means that unprivileged users could create
 a raw socket, aka CID-e69dbd4619e7. (bnc#1152789)
- CVE-2019-16413: The 9p filesystem did not protect i_size_write() properly, which caused an
 i_size_read() infinite loop and denial of service on SMP systems. (bnc#1151347)
- CVE-2019-15291: There was a NULL pointer dereference caused by a malicious USB device in the
 flexcop_usb_probe ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 11-SP4.");

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

if(release == "SLES11.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~3.0.101~108.108.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-extra", rpm:"kernel-pae-extra~3.0.101~108.108.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-extra", rpm:"kernel-ppc64-extra~3.0.101~108.108.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-extra", rpm:"kernel-trace-extra~3.0.101~108.108.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-extra", rpm:"kernel-xen-extra~3.0.101~108.108.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem", rpm:"kernel-bigmem~3.0.101~108.108.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem-base", rpm:"kernel-bigmem-base~3.0.101~108.108.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem-devel", rpm:"kernel-bigmem-devel~3.0.101~108.108.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~108.108.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~108.108.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~108.108.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.101~108.108.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~108.108.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~108.108.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~108.108.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.101~108.108.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.101~108.108.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.101~108.108.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~3.0.101~108.108.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-base", rpm:"kernel-ppc64-base~3.0.101~108.108.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-devel", rpm:"kernel-ppc64-devel~3.0.101~108.108.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~108.108.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~108.108.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~108.108.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~108.108.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~108.108.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~108.108.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~108.108.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~108.108.1", rls:"SLES11.0SP4"))) {
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
