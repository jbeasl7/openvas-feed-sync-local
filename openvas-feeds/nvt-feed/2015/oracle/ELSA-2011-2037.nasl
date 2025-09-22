# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122029");
  script_cve_id("CVE-2011-1020", "CVE-2011-1577", "CVE-2011-1585", "CVE-2011-2495", "CVE-2011-2525", "CVE-2011-2707", "CVE-2011-3638", "CVE-2011-4110", "CVE-2011-4330");
  script_tag(name:"creation_date", value:"2015-10-06 11:11:55 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-04 15:13:00 +0000 (Tue, 04 Aug 2020)");

  script_name("Oracle: Security Advisory (ELSA-2011-2037)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux5|OracleLinux6)");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-2037");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-2037.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-uek, ofa-2.6.32-300.3.1.el5uek, ofa-2.6.32-300.3.1.el6uek' package(s) announced via the ELSA-2011-2037 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-300.3.1.el6uek]
- proc: fix oops on invalid /proc//maps access (Linux Torvalds)- Revert 'capabilities: do not grant full privs for setuid w/ file caps + no effective caps' (Joe Jin)- [mm]: Use MMF_COMPAT instead ia32_compat to prevent kabi be broken (Joe Jin)- proc: enable writing to /proc/pid/mem (Stephen Wilson)- proc: make check_mem_permission() return an mm_struct on success (Stephen Wilson)- proc: hold cred_guard_mutex in check_mem_permission() (Joe Jin)- proc: disable mem_write after exec (Stephen Wilson)- mm: implement access_remote_vm (Stephen Wilson)- mm: factor out main logic of access_process_vm (Stephen Wilson)- mm: use mm_struct to resolve gate vma's in __get_user_pages (Stephen Wilson)- mm: arch: rename in_gate_area_no_task to in_gate_area_no_mm (Stephen Wilson)- mm: arch: make in_gate_area take an mm_struct instead of a task_struct (Stephen Wilson)- mm: arch: make get_gate_vma take an mm_struct instead of a task_struct (Stephen Wilson)- x86: mark associated mm when running a task in 32 bit compatibility mode (Stephen Wilson)- x86: add context tag to mark mm when running a task in 32-bit compatibility mode (Stephen Wilson)- auxv: require the target to be tracable (or yourself) (Al Viro)- close race in /proc/*/environ (Al Viro)- report errors in /proc/*/*map* sanely (Al Viro)- pagemap: close races with suid execve (Al Viro)- make sessionid permissions in /proc/*/task/* match those in /proc/* (Al Viro)- Revert 'report errors in /proc/*/*map* sanely' (Joe Jin)- Revert 'proc: fix oops on invalid /proc//maps access' (Joe Jin)[2.6.32-300.2.1.el6uek]- [kabi] Add missing kabi (Srinivas Maturi)- report errors in /proc/*/*map* sanely (Joe Jin)[2.6.32-300.1.1.el6uek]- [SCSI] qla4xxx: fix build error for OL6 (Joe Jin)- Ecryptfs: Add mount option to check uid of device being mounted = expect uid (Maxim Uvarov)- proc: fix oops on invalid /proc//maps access (Linus Torvalds)- x86/mm: Fix pgd_lock deadlock (Joe Jin)- x86, mm: Hold mm->page_table_lock while doing vmalloc_sync (Joe Jin)- proc: restrict access to /proc/PID/io (Vasiliy Kulikov)- futex: Fix regression with read only mappings (Shawn Bohrer)- x86-32, vdso: On system call restart after SYSENTER, use int db_5.ELSA-2011-2037x80 (H. Peter Anvin)- x86, UV: Remove UV delay in starting slave cpus (Jack Steiner)- Include several Xen pv hugepage fixes. (Dave McCracken)- GRO: fix merging a paged skb after non-paged skbs (Michal Schmidt)- md/linear: avoid corrupting structure while waiting for rcu_free to complete. (NeilBrown)- xen: x86_32: do not enable interrupts when returning from exception in interrupt context (Igor Mammedov)- xen/smp: Warn user why they keel over - nosmp or noapic and what to use instead. (Konrad Rzeszutek Wilk)- hvc_console: Improve tty/console put_chars handling (Hendrik Brueckner)- 3w-9xxx: fix iommu_iova leak (James Bottomley)- aacraid: reset should disable MSI interrupt (Vasily Averin)- ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel-uek, ofa-2.6.32-300.3.1.el5uek, ofa-2.6.32-300.3.1.el6uek' package(s) on Oracle Linux 5, Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.32~300.3.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.32~300.3.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.32~300.3.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.32~300.3.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.32~300.3.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.32~300.3.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-headers", rpm:"kernel-uek-headers~2.6.32~300.3.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofa-2.6.32-300.3.1.el5uek", rpm:"ofa-2.6.32-300.3.1.el5uek~1.5.1~4.0.53", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofa-2.6.32-300.3.1.el5uekdebug", rpm:"ofa-2.6.32-300.3.1.el5uekdebug~1.5.1~4.0.53", rls:"OracleLinux5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.32~300.3.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.32~300.3.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.32~300.3.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.32~300.3.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.32~300.3.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.32~300.3.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-headers", rpm:"kernel-uek-headers~2.6.32~300.3.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofa-2.6.32-300.3.1.el6uek", rpm:"ofa-2.6.32-300.3.1.el6uek~1.5.1~4.0.47", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofa-2.6.32-300.3.1.el6uekdebug", rpm:"ofa-2.6.32-300.3.1.el6uekdebug~1.5.1~4.0.47", rls:"OracleLinux6"))) {
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
