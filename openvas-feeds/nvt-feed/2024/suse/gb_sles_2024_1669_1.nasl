# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.1669.1");
  script_cve_id("CVE-2021-46904", "CVE-2021-46905", "CVE-2021-46932", "CVE-2022-48619", "CVE-2023-28746", "CVE-2023-31083", "CVE-2023-51780", "CVE-2023-51782", "CVE-2023-52340", "CVE-2023-52429", "CVE-2023-52445", "CVE-2023-52449", "CVE-2023-52475", "CVE-2023-52590", "CVE-2023-52591", "CVE-2023-6270", "CVE-2024-23851", "CVE-2024-26733", "CVE-2024-26898", "CVE-2024-27043");
  script_tag(name:"creation_date", value:"2024-08-20 04:27:44 +0000 (Tue, 20 Aug 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-23 19:13:31 +0000 (Mon, 23 Dec 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:1669-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1669-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20241669-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210780");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213456");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218220");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218730");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218757");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219146");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219295");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219827");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220191");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220238");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220241");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220416");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220418");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220444");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220649");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221044");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221088");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221578");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221598");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222585");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222619");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223016");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223824");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-August/019269.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2024:1669-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP4 kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2024-27043: Fixed a use-after-free in edia/dvbdev in different places (bsc#1223824).
- CVE-2024-26733: Fixed an overflow in arp_req_get() in arp (bsc#1222585).
- CVE-2022-48619: Fixed a denial-of-service issue in drivers/input/input.c (bsc#1218220).
- CVE-2021-46904: Fixed NULL pointer dereference during tty device unregistration (bsc#1220416).
- CVE-2023-28746: Fixed Register File Data Sampling (bsc#1213456).
- CVE-2021-46905: Fixed NULL pointer dereference on disconnect regression (bsc#1220418).
- CVE-2023-52340: Fixed a denial of service related to ICMPv6 'Packet Too Big' packets (bsc#1219295).
- CVE-2021-46932: Initialized work before appletouch device registration (bsc#1220444).
- CVE-2023-52449: Fixed gluebi NULL pointer dereference caused by ftl notifier (bsc#1220238).
- CVE-2023-52475: Fixed a use-after-free in powermate_config_complete() (bsc#1220649).
- CVE-2023-52445: Fixed a use-after-free on context disconnection in pvrusb2 (bsc#1220241).
- CVE-2023-52429: Limited the number of targets and parameter size area for device mapper (bsc#1219146).
- CVE-2023-51780: Fixed a use-after-free in do_vcc_ioctl() related to a vcc_recvmsg race condition (bsc#1218730).
- CVE-2023-51782: Fixed a use-after-free in rose_ioctl() related to a rose_accept race condition (bsc#1218757).
- CVE-2023-31083: Fixed a NULL pointer dereference in hci_uart_tty_ioctl() (bsc#1210780).

The following non-security bugs were fixed:

- KVM: VMX: Move VERW closer to VMentry for MDS mitigation (git-fixes).
- KVM: VMX: Use BT+JNC, i.e. EFLAGS.CF to select VMRESUME vs. VMLAUNCH (git-fixes).
- tty: n_gsm: require CAP_NET_ADMIN to attach N_GSM0710 ldisc (bsc#1222619).
- x86/asm: Add _ASM_RIP() macro for x86-64 (%rip) suffix (git-fixes).
- x86/bugs: Add asm helpers for executing VERW (bsc#1213456).
- x86/bugs: Use ALTERNATIVE() instead of mds_user_clear static key (git-fixes).
- x86/entry_32: Add VERW just before userspace transition (git-fixes).
- x86/entry_64: Add VERW just before userspace transition (git-fixes).");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~108.153.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~108.153.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~108.153.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~108.153.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~108.153.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~108.153.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~108.153.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~108.153.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~108.153.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~108.153.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~108.153.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~108.153.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~108.153.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~108.153.1", rls:"SLES11.0SP4"))) {
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
