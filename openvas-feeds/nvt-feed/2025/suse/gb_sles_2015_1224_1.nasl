# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.1224.1");
  script_cve_id("CVE-2014-9710", "CVE-2014-9728", "CVE-2014-9729", "CVE-2014-9730", "CVE-2014-9731", "CVE-2015-1420", "CVE-2015-1805", "CVE-2015-2041", "CVE-2015-2922", "CVE-2015-3636", "CVE-2015-4700", "CVE-2015-5364", "CVE-2015-5366");
  script_tag(name:"creation_date", value:"2025-02-13 14:53:48 +0000 (Thu, 13 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:1224-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:1224-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20151224-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915517");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/919007");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/922583");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/923908");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/927355");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/929525");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/929647");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/930786");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/933429");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/933896");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/933904");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/933907");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935705");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/936831");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-July/001490.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2015:1224-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP3 Teradata kernel was updated to fix the following bugs and security issues.

The following security issues have been fixed:

- Update patches.fixes/udp-fix-behavior-of-wrong-checksums.patch (bsc#936831, CVE-2015-5364, CVE-2015-5366).
- Btrfs: make xattr replace operations atomic (bnc#923908, CVE-2014-9710).
- udp: fix behavior of wrong checksums (bsc#936831, CVE-2015-5364, CVE-2015-5366).
- vfs: read file_handle only once in handle_to_path (bsc#915517, CVE-2015-1420).
- x86: bpf_jit: fix compilation of large bpf programs (bnc#935705,CVE-2015-4700).
- udf: Check length of extended attributes and allocation (bsc#936831, CVE-2015-5364, CVE-2015-5366).
- Update patches.fixes/udf-Check-component-length-before-reading-it.patch (bsc#933904, CVE-2014-9728, CVE-2014-9730).
- Update patches.fixes/udf-Verify-i_size-when-loading-inode.patch (bsc#933904, CVE-2014-9728, CVE-2014-9729).
- Update patches.fixes/udf-Verify-symlink-size-before-loading-it.patch (bsc#933904, CVE-2014-9728).
- Update patches.fixes/udf-Check-path-length-when-reading-symlink.patch (bnc#933896, CVE-2014-9731).
- pipe: fix iov overrun for failed atomic copy (bsc#933429, CVE-2015-1805).
- ipv6: Don't reduce hop limit for an interface (bsc#922583, CVE-2015-2922).
- net: llc: use correct size for sysctl timeout entries (bsc#919007, CVE-2015-2041).
- ipv4: Missing sk_nulls_node_init() in ping_unhash() (bsc#929525, CVE-2015-3636).
- ipv6: Don't reduce hop limit for an interface (bsc#922583, CVE-2015-2922).
- net: llc: use correct size for sysctl timeout entries (bsc#919007, CVE-2015-2041).
- ipv4: Missing sk_nulls_node_init() in ping_unhash() (bsc#929525, CVE-2015-3636).

The following non-security issues have been fixed:

- mlx4: Check for assigned VFs before disabling SR-IOV (bsc#927355).
- ixgbe: Use pci_vfs_assigned instead of ixgbe_vfs_are_assigned (bsc#927355).
- pci: Add SRIOV helper function to determine if VFs are assigned to guest (bsc#927355).
- net/mlx4_core: Don't disable SRIOV if there are active VFs (bsc#927355).
- udf: Remove repeated loads blocksize (bsc#933907).
- Refresh patches.fixes/deal-with-deadlock-in-d_walk-fix.patch. based on 3.2 stable fix 20defcec264c ('dcache: Fix locking bugs in backported 'deal with deadlock in d_walk()''). Not harmfull for regular SLES kernels but RT or PREEMPT kernels would see disbalance.
- sched: Fix potential near-infinite distribute_cfs_runtime() loop (bnc#930786)
- tty: Correct tty buffer flush (bnc#929647).
- tty: hold lock across tty buffer finding and buffer filling (bnc#929647).");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 11-SP3.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~0.63.TDC.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~0.63.TDC.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~0.63.TDC.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~0.63.TDC.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~0.63.TDC.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~0.63.TDC.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~0.63.TDC.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~0.63.TDC.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~0.63.TDC.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~0.63.TDC.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~0.63.TDC.1", rls:"SLES11.0SP3"))) {
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
