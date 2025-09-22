# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123597");
  script_cve_id("CVE-2012-6548", "CVE-2013-0914", "CVE-2013-1848", "CVE-2013-2128", "CVE-2013-2634", "CVE-2013-2635", "CVE-2013-2852", "CVE-2013-3222", "CVE-2013-3224", "CVE-2013-3225", "CVE-2013-3301");
  script_tag(name:"creation_date", value:"2015-10-06 11:06:02 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-03 15:09:00 +0000 (Mon, 03 Aug 2020)");

  script_name("Oracle: Security Advisory (ELSA-2013-1051)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-1051");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-1051.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2013-1051 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-358.14.1]
- [x86] apic: Add probe() for apic_flat (Prarit Bhargava) [975086 953342]

[2.6.32-358.13.1]
- [wireless] b43: stop format string leaking into error msgs (John Linville) [971387 971389] {CVE-2013-2852}
- [pci] make sriov work with hotplug remove (Takahiro MUNEDA) [973555 965002]
- [net] rtnl: fix info leak on RTM_GETLINK request for VF devices (Flavio Leitner) [923657 923659] {CVE-2013-2634 CVE-2013-2635}
- [net] dcbnl: fix various netlink info leaks (Flavio Leitner) [923657 923659] {CVE-2013-2634 CVE-2013-2635}
- [net] bonding: fix enslaving in alb mode when link down (Veaceslav Falico) [969306 965132]
- [net] tcp: Fix oops from tcp_collapse() when using splice() (Nikola Pajkovsky) [968871 863512] {CVE-2013-2128}
- [usb] uhci: fix IRQ race during initialization (Dave Young) [968557 915834]
- [netdrv] e1000e: enable VLAN RX/TX in PROMISC mode (Stefan Assmann) [963564 886420]
- [netdrv] bnx2x: strip VLAN header in PROMISC mode (Stefan Assmann) [963564 886420]
- [net] vlan: handle packets with empty vlan_group via VLAN code (Stefan Assmann) [963564 886420]
- [fs] namei.c: Don't allow to create hardlink for deleted file (Brian Foster) [956296 908158]
- [fs] gfs2: Reinstate withdraw ack system (Robert S Peterson) [927308 908093]
- [fs] nfs: open a file descriptor for fsync in nfs4 recovery (J. Bruce Fields) [964046 915479]
- [net] macvlan: remove bogus check in macvlan_handle_frame() (Jiri Pirko) [962370 952785]
- [net] macvlan: fix passthru mode race between dev removal and rx path (Jiri Pirko) [962370 952785]
- [kernel] rcu: Replace list_first_entry_rcu() with list_first_or_null_rcu() (Jiri Pirko) [962370 952785]
- [net] bluetooth/rfcomm: Fix missing msg_namelen update in rfcomm_sock_recvmsg() (Weiping Pan) [955653 955654] {CVE-2013-3225}
- [net] bluetooth: fix possible info leak in bt_sock_recvmsg() (Radomir Vrbovsky) [955603 955604] {CVE-2013-3224}
- [fs] gfs2: Issue discards in 512b sectors (Robert S Peterson) [927317 922779]
- [fs] udf: avoid info leak on export (Nikola Pajkovsky) [922354 922355] {CVE-2012-6548}
- [scsi] lpfc: Fixed deadlock between hbalock and nlp_lock use (Rob Evers) [962368 960717]
- [kernel] tracing: Fix possible NULL pointer dereferences (Weiping Pan) [952212 952213] {CVE-2013-3301}
- [kernel] tracing: Fix panic when lseek() called on 'trace' opened for writing (Weiping Pan) [952212 952213] {CVE-2013-3301}
- [net] atm: update msg_namelen in vcc_recvmsg() (Nikola Pajkovsky) [955224 955225] {CVE-2013-3222}
- [x86] apic: Work around boot failure on HP ProLiant DL980 G7 Server systems (Prarit Bhargava) [969326 912963]
- [x86] apic: Use probe routines to simplify apic selection (Prarit Bhargava) [969326 912963]
- [x86] x2apic: Simplify apic init in SMP and UP builds (Prarit Bhargava) [969326 912963]
- [kvm] vmx: provide the vmclear function and a bitmap to support VMCLEAR in kdump (Andrew Jones) [962372 908608]
- [x86] kexec: VMCLEAR ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~358.14.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~358.14.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~358.14.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~358.14.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~358.14.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~358.14.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~358.14.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~358.14.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~358.14.1.el6", rls:"OracleLinux6"))) {
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
