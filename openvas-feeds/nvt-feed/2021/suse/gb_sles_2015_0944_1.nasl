# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0944.1");
  script_cve_id("CVE-2012-5510", "CVE-2012-5511", "CVE-2012-5512", "CVE-2012-5513", "CVE-2012-5514", "CVE-2012-5515", "CVE-2012-5634", "CVE-2012-6075", "CVE-2013-0153", "CVE-2013-0154", "CVE-2015-3340", "CVE-2015-3456");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:12 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0944-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0944-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150944-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/777628");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/789940");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/789944");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/789945");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/789948");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/789950");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/789951");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/789988");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/792476");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/793927");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/794316");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/797014");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/797031");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/797523");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/798188");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/799694");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/800156");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/800275");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/802690");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/805094");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/806736");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/910441");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/927967");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/929339");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-May/001408.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Xen' package(s) announced via the SUSE-SU-2015:0944-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"XEN has been updated to fix various bugs and security issues:

 *

 CVE-2013-0153: (XSA 36) To avoid an erratum in early hardware, the
 Xen AMD IOMMU code by default choose to use a single interrupt
 remapping table for the whole system. This sharing implied that any
 guest with a passed through PCI device that is bus mastering capable
 can inject interrupts into other guests, including domain 0. This has
 been disabled for AMD chipsets not capable of it.

 *

 CVE-2012-6075: qemu: The e1000 had overflows under some conditions,
 potentially corrupting memory.

 *

 CVE-2013-0154: (XSA 37) Hypervisor crash due to incorrect ASSERT
 (debug build only)

 *

 CVE-2012-5634: (XSA-33) A VT-d interrupt remapping source validation
 flaw was fixed.

Also the following bugs have been fixed:

 * bnc#805094 - xen hot plug attach/detach fails
 * bnc#802690 - domain locking can prevent a live migration from
 completing
 * bnc#797014 - no way to control live migrations
 o fix logic error in stdiostream_progress
 o restore logging in xc_save
 o add options to control migration tunables
 * bnc#806736: enabling xentrace crashes hypervisor
 * Upstream patches from Jan 26287-sched-credit-pick-idle.patch
 26501-VMX-simplify-CR0-update.patch
 26502-VMX-disable-SMEP-when-not-paging.patch
 26516-ACPI-parse-table-retval.patch (Replaces
 CVE-2013-0153-xsa36.patch) 26517-AMD-IOMMU-clear-irtes.patch
 (Replaces CVE-2013-0153-xsa36.patch)
 26518-AMD-IOMMU-disable-if-SATA-combined-mode.patch (Replaces
 CVE-2013-0153-xsa36.patch)
 26519-AMD-IOMMU-perdev-intremap-default.patch (Replaces
 CVE-2013-0153-xsa36.patch) 26526-pvdrv-no-devinit.patch
 26531-AMD-IOMMU-IVHD-special-missing.patch (Replaces
 CVE-2013-0153-xsa36.patch)
 * bnc#798188 - Add $network to xend initscript dependencies
 * bnc#799694 - Unable to dvd or cdrom-boot DomU after xen-tools update
 Fixed with update to Xen version 4.1.4
 * bnc#800156 - L3: HP iLo Generate NMI function not working in XEN
 kernel
 * Upstream patches from Jan 26404-x86-forward-both-NMI-kinds.patch
 26427-x86-AMD-enable-WC+.patch
 * bnc#793927 - Xen VMs with more than 2 disks randomly fail to start
 * Upstream patches from Jan 26332-x86-compat-show-guest-stack-mfn.patch
 26333-x86-get_page_type-assert.patch (Replaces
 CVE-2013-0154-xsa37.patch)
 26340-VT-d-intremap-verify-legacy-bridge.patch (Replaces
 CVE-2012-5634-xsa33.patch) 26370-libxc-x86-initial-mapping-fit.patch
 * Update to Xen 4.1.4 c/s 23432
 * Update xenpaging.guest-memusage.patch add rule for xenmem to avoid
 spurious build failures
 * Upstream patches from Jan 26179-PCI-find-next-cap.patch
 26183-x86-HPET-masking.patch 26188-x86-time-scale-asm.patch
 26200-IOMMU-debug-verbose.patch 26203-x86-HAP-dirty-vram-leak.patch
 26229-gnttab-version-switch.patch (Replaces
 CVE-2012-5510-xsa26.patch) 26230-x86-HVM-limit-batches.patch
 (Replaces CVE-2012-5511-xsa27.patch)
 26231-memory-exchange-checks.patch (Replaces
 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Xen' package(s) on SUSE Linux Enterprise Server 11-SP2, SUSE Linux Enterprise Server for SAP Applications 11-SP2.");

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

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.1.4_02~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~4.1.6_08~0.11.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.1.4_02~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-pdf", rpm:"xen-doc-pdf~4.1.4_02~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.1.4_02_3.0.58_0.6.6~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.1.4_02_3.0.58_0.6.6~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-trace", rpm:"xen-kmp-trace~4.1.4_02_3.0.58_0.6.6~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.1.4_02~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.1.4_02~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.1.4_02~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.1.4_02~0.5.1", rls:"SLES11.0SP2"))) {
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
