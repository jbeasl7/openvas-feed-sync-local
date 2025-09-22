# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2013.1923.1");
  script_cve_id("CVE-2013-1922", "CVE-2013-2007", "CVE-2013-4375", "CVE-2013-4416", "CVE-2013-4494", "CVE-2013-4551", "CVE-2013-4553", "CVE-2013-4554", "CVE-2013-6375");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:22 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2013:1923-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2013:1923-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2013/suse-su-20131923-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Xen' package(s) announced via the SUSE-SU-2013:1923-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Xen hypervisor and tool-suite have been updated to fix security issues and bugs:

 * CVE-2013-4494: XSA-73: A lock order reversal between page allocation and grant table locks could lead to host crashes or even host code execution.
 * CVE-2013-4553: XSA-74: A lock order reversal between page_alloc_lock and mm_rwlock could lead to deadlocks.
 * CVE-2013-4554: XSA-76: Hypercalls exposed to privilege rings 1 and 2 of HVM guests which might lead to Hypervisor escalation under specific circumstances.
 * CVE-2013-6375: XSA-78: Insufficient TLB flushing in VT-d (iommu) code could lead to access of memory that was revoked.
 * CVE-2013-4551: XSA-75: A host crash due to guest VMX instruction execution was fixed.

Non-security bugs have also been fixed:

 * bnc#840997: It is possible to start a VM twice on the same node.
 * bnc#842417: In HP's UEFI x86_64 platform and SLES 11-SP3, dom0 will could lock-up on multiple blades nPar.
 * bnc#848014: Xen Hypervisor panics on 8-blades nPar with 46-bit memory addressing.
 * bnc#846849: Soft lock-up with PCI pass-through and many VCPUs.
 * bnc#833483: Boot Failure with Xen kernel in UEFI mode with error 'No memory for trampoline'.
 * Increase the maximum supported CPUs in the Hypervisor to 512.

Security Issues:

 * CVE-2013-1922
>
 * CVE-2013-2007
>
 * CVE-2013-4375
>
 * CVE-2013-4416
>
 * CVE-2013-4494
>
 * CVE-2013-4551
>
 * CVE-2013-4553
>
 * CVE-2013-4554
>");

  script_tag(name:"affected", value:"'Xen' package(s) on SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Software Development Kit 11-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.2.3_08~0.7.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.2.3_08~0.7.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-pdf", rpm:"xen-doc-pdf~4.2.3_08~0.7.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.2.3_08_3.0.101_0.8~0.7.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.2.3_08_3.0.101_0.8~0.7.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.2.3_08~0.7.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.2.3_08~0.7.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.2.3_08~0.7.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.2.3_08~0.7.1", rls:"SLES11.0SP3"))) {
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
