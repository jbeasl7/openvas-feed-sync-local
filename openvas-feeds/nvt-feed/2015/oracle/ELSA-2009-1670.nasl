# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122408");
  script_cve_id("CVE-2009-3612", "CVE-2009-3620", "CVE-2009-3621", "CVE-2009-3726");
  script_tag(name:"creation_date", value:"2015-10-08 11:44:45 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-03 17:13:00 +0000 (Fri, 03 Nov 2023)");

  script_name("Oracle: Security Advisory (ELSA-2009-1670)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2009-1670");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2009-1670.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-164.9.1.0.1.el5, oracleasm-2.6.18-164.9.1.0.1.el5' package(s) announced via the ELSA-2009-1670 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.18-164.9.1.0.1.el5]
- [xen] check to see if hypervisor supports memory reservation change (Chuck Anderson) [orabug 7556514]
- Add entropy support to igb ( John Sobecki) [orabug 7607479]
- [nfs] convert ENETUNREACH to ENOTCONN [orabug 7689332]
- [NET] Add xen pv/bonding netconsole support (Tina yang) [orabug 6993043] [bz 7258]
- [MM] shrink zone patch (John Sobecki,Chris Mason) [orabug 6086839]
- fix aacraid not to reset during kexec (Joe Jin) [orabug 8516042]
- [nfsd] fix failure of file creation from hpux client (Wen gang Wang) [orabug 7579314]

[2.6.18-164.9.1.el5]
- [x86] fix stale data in shared_cpu_map cpumasks (Prarit Bhargava) [545583 541953]

[2.6.18-164.8.1.el5]
- [xen] iommu-amd: extend loop ctr for polling completion wait (Bhavna Sarathy ) [539687 518474 526766]
- [xen] iommu: add passthrough and no-intremap parameters (Bhavna Sarathy ) [539687 518474 526766]
- [xen] iommu: enable amd iommu debug at run-time (Bhavna Sarathy ) [539687 518474 526766]
- [xen] support interrupt remapping on M-C (Bhavna Sarathy ) [539687 518474 526766]
- [xen] iommu: move iommu_setup() to setup ioapic correctly (Bhavna Sarathy ) [539687 518474 526766]
- [net] bnx2x: add support for bcm8727 phy (Stanislaw Gruszka ) [540381 515716]
- [x86] cpu: upstream cache fixes needed for amd m-c (Bhavna Sarathy ) [540469 526315]
- [x86_64] set proc id and core id before calling fixup_dcm (Bhavna Sarathy) [540469 526315]
- [x86] mce_amd: fix up threshold_bank4 creation (Bhavna Sarathy ) [540469 526315]
- Revert: [net] sched: fix panic in bnx2_poll_work (John Feeney ) [539686 526481]
- FP register state is corrupted during the handling a SIGSEGV (Chuck Anderson)
 [orabug 7708133]

[2.6.18-164.7.1.el5]
- [xen] fix numa on magny-cours systems (Bhavna Sarathy ) [539684 526051]
- [xen] fix crash with memory imbalance (Bhavna Sarathy ) [539690 526785]
- [net] sched: fix panic in bnx2_poll_work (John Feeney ) [539686 526481]
- [acpi] prevent duplicate dirs in /proc/acpi/processor (Matthew Garrett ) [539692 537395]
- [x86] fix boot crash with < 8-core AMD Magny-cours system (Bhavna Sarathy) [539682 522215]
- [x86] support amd magny-cours power-aware scheduler fix (Bhavna Sarathy ) [539680 513685]
- [x86] disable NMI watchdog on CPU remove (Prarit Bhargava ) [539691 532514]
- [acpi] bm_check and bm_control update (Luming Yu ) [539677 509422]
- [x86_64] amd: iommu system management erratum 63 fix (Bhavna Sarathy ) [539689 531469]
- [net] bnx2i/cnic: update driver version for RHEL5.5 (Mike Christie ) [537014 516233]
- [x86] fix L1 cache by adding missing break (Bhavna Sarathy ) [539688 526770]
- [x86] amd: fix hot plug cpu issue on 32-bit magny-cours (Bhavna Sarathy ) [539688 526770]
- [acpi] disable ARB_DISABLE on platforms where not needed (Luming Yu ) [539677 509422]
- [fs] private dentry list to avoid dcache_lock contention (Lachlan McIlroy ) [537019 526612]
- [scsi] qla2xxx: enable msi-x correctly ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-164.9.1.0.1.el5, oracleasm-2.6.18-164.9.1.0.1.el5' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~164.9.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~164.9.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~164.9.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~164.9.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~164.9.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~164.9.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~164.9.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~164.9.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~164.9.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~164.9.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-164.9.1.0.1.el5", rpm:"ocfs2-2.6.18-164.9.1.0.1.el5~1.4.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-164.9.1.0.1.el5PAE", rpm:"ocfs2-2.6.18-164.9.1.0.1.el5PAE~1.4.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-164.9.1.0.1.el5debug", rpm:"ocfs2-2.6.18-164.9.1.0.1.el5debug~1.4.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-164.9.1.0.1.el5xen", rpm:"ocfs2-2.6.18-164.9.1.0.1.el5xen~1.4.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-164.9.1.0.1.el5", rpm:"oracleasm-2.6.18-164.9.1.0.1.el5~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-164.9.1.0.1.el5PAE", rpm:"oracleasm-2.6.18-164.9.1.0.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-164.9.1.0.1.el5debug", rpm:"oracleasm-2.6.18-164.9.1.0.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-164.9.1.0.1.el5xen", rpm:"oracleasm-2.6.18-164.9.1.0.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5"))) {
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
