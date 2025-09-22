# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2013.1075.1");
  script_cve_id("CVE-2013-1917", "CVE-2013-1918", "CVE-2013-1919", "CVE-2013-1920", "CVE-2013-1952", "CVE-2013-1964", "CVE-2013-2072", "CVE-2013-2076", "CVE-2013-2077", "CVE-2013-2078");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:24 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.4");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2013:1075-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2013:1075-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2013/suse-su-20131075-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Xen' package(s) announced via the SUSE-SU-2013:1075-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"XEN has been updated to 4.1.5 c/s 23509 to fix various bugs and security issues.

The following security issues have been fixed:

 *

 CVE-2013-1918: Certain page table manipulation operations in Xen 4.1.x, 4.2.x, and earlier were not preemptible, which allowed local PV kernels to cause a denial of service via vectors related to deep page table traversal.

 *

 CVE-2013-1952: Xen 4.x, when using Intel VT-d for a bus mastering capable PCI device, did not properly check the source when accessing a bridge devices interrupt remapping table entries for MSI interrupts, which allowed local guest domains to cause a denial of service (interrupt injection) via unspecified vectors.

 *

 CVE-2013-2076: A information leak in the XSAVE/XRSTOR instructions could be used to determine state of floating point operations in other domains.

 *

 CVE-2013-2077: A denial of service (hypervisor crash)
was possible due to missing exception recovery on XRSTOR,
that could be used to crash the machine by PV guest users.

 *

 CVE-2013-2078: A denial of service (hypervisor crash)
was possible due to missing exception recovery on XSETBV,
that could be used to crash the machine by PV guest users.

 *

 CVE-2013-2072: Systems which allow untrusted administrators to configure guest vcpu affinity may be exploited to trigger a buffer overrun and corrupt memory.

 *

 CVE-2013-1917: Xen 3.1 through 4.x, when running 64-bit hosts on Intel CPUs, did not clear the NT flag when using an IRET after a SYSENTER instruction, which allowed PV guest users to cause a denial of service (hypervisor crash) by triggering a #GP fault, which is not properly handled by another IRET instruction.

 *

 CVE-2013-1919: Xen 4.2.x and 4.1.x did not properly restrict access to IRQs, which allowed local stub domain clients to gain access to IRQs and cause a denial of service via vectors related to 'passed-through IRQs or PCI devices.'

 *

 CVE-2013-1920: Xen 4.2.x, 4.1.x, and earlier, when the hypervisor is running 'under memory pressure' and the Xen Security Module (XSM) is enabled, used the wrong ordering of operations when extending the per-domain event channel tracking table, which caused a use-after-free and allowed local guest kernels to inject arbitrary events and gain privileges via unspecified vectors.

 *

 CVE-2013-1964: Xen 4.0.x and 4.1.x incorrectly released a grant reference when releasing a non-v1,
non-transitive grant, which allowed local guest administrators to cause a denial of service (host crash),
obtain sensitive information, or possible have other impacts via unspecified vectors.

Bugfixes:

 *

 Upstream patches from Jan 26956-x86-mm-preemptible-cleanup.patch 27071-x86-IO-APIC-fix-guest-RTE-write-corner-cases.patch 27072-x86-shadow-fix-off-by-one-in-MMIO-permission-check.pat ch 27079-fix-XSA-46-regression-with-xend-xm.patch 27083-AMD-iommu-SR56x0-Erratum-64-Reset-all-head-tail-pointe rs.patch

 *

 Update ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Xen' package(s) on SUSE Linux Enterprise Desktop 11-SP2, SUSE Linux Enterprise Server 11-SP2, SUSE Linux Enterprise Software Development Kit 11-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.1.5_02~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.1.5_02~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-pdf", rpm:"xen-doc-pdf~4.1.5_02~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.1.5_02_3.0.74_0.6.10~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.1.5_02_3.0.74_0.6.10~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-trace", rpm:"xen-kmp-trace~4.1.5_02_3.0.74_0.6.10~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.1.5_02~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.1.5_02~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.1.5_02~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.1.5_02~0.5.1", rls:"SLES11.0SP2"))) {
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
