# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2014.0470.1");
  script_cve_id("CVE-2012-4535", "CVE-2012-4537", "CVE-2012-4544", "CVE-2012-5513", "CVE-2012-5515", "CVE-2013-1917", "CVE-2013-1920", "CVE-2013-2194", "CVE-2013-2195", "CVE-2013-2196", "CVE-2013-4355", "CVE-2013-4368", "CVE-2013-4494", "CVE-2013-4554", "CVE-2013-6885");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:21 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2014:0470-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2014:0470-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2014/suse-su-20140470-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Xen' package(s) announced via the SUSE-SU-2014:0470-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 10 Service Pack 3 LTSS Xen hypervisor and toolset have been updated to fix various security issues:

The following security issues have been addressed:

 *

 XSA-20: CVE-2012-4535: Xen 3.4 through 4.2, and possibly earlier versions, allows local guest OS administrators to cause a denial of service (Xen infinite loop and physical CPU consumption) by setting a VCPU with an 'inappropriate deadline'. (bnc#786516)

 *

 XSA-22: CVE-2012-4537: Xen 3.4 through 4.2, and possibly earlier versions, does not properly synchronize the p2m and m2p tables when the set_p2m_entry function fails, which allows local HVM guest OS administrators to cause a denial of service (memory consumption and assertion failure), aka 'Memory mapping failure DoS vulnerability'.
(bnc#786517)

 *

 XSA-25: CVE-2012-4544: The PV domain builder in Xen 4.2 and earlier does not validate the size of the kernel or ramdisk (1) before or (2) after decompression, which allows local guest administrators to cause a denial of service
(domain 0 memory consumption) via a crafted (a) kernel or
(b) ramdisk. (bnc#787163)

 *

 XSA-29: CVE-2012-5513: The XENMEM_exchange handler in Xen 4.2 and earlier does not properly check the memory address, which allows local PV guest OS administrators to cause a denial of service (crash) or possibly gain privileges via unspecified vectors that overwrite memory in the hypervisor reserved range. (bnc#789951)

 *

 XSA-31: CVE-2012-5515: The (1)
XENMEM_decrease_reservation, (2) XENMEM_populate_physmap,
and (3) XENMEM_exchange hypercalls in Xen 4.2 and earlier allow local guest administrators to cause a denial of service (long loop and hang) via a crafted extent_order value. (bnc#789950)

 *

 XSA-44: CVE-2013-1917: Xen 3.1 through 4.x, when running 64-bit hosts on Intel CPUs, does not clear the NT flag when using an IRET after a SYSENTER instruction, which allows PV guest users to cause a denial of service
(hypervisor crash) by triggering a #GP fault, which is not properly handled by another IRET instruction. (bnc#813673)

 *

 XSA-47: CVE-2013-1920: Xen 4.2.x, 4.1.x, and earlier,
when the hypervisor is running 'under memory pressure' and the Xen Security Module (XSM) is enabled, uses the wrong ordering of operations when extending the per-domain event channel tracking table, which causes a use-after-free and allows local guest kernels to inject arbitrary events and gain privileges via unspecified vectors. (bnc#813677)

 *

 XSA-55: CVE-2013-2196: Multiple unspecified vulnerabilities in the Elf parser (libelf) in Xen 4.2.x and earlier allow local guest administrators with certain permissions to have an unspecified impact via a crafted kernel, related to 'other problems' that are not CVE-2013-2194 or CVE-2013-2195. (bnc#823011)

 *

 XSA-55: CVE-2013-2195: The Elf parser (libelf) in Xen 4.2.x and earlier allow local guest administrators with certain permissions to ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Xen' package(s) on SUSE Linux Enterprise Server 10-SP3.");

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

if(release == "SLES10.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~3.2.3_17040_28~0.6.21.3", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~3.2.3_17040_28~0.6.21.3", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~3.2.3_17040_28~0.6.21.3", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-pdf", rpm:"xen-doc-pdf~3.2.3_17040_28~0.6.21.3", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-ps", rpm:"xen-doc-ps~3.2.3_17040_28~0.6.21.3", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-bigsmp", rpm:"xen-kmp-bigsmp~3.2.3_17040_28_2.6.16.60_0.113.9~0.6.21.3", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-debug", rpm:"xen-kmp-debug~3.2.3_17040_28_2.6.16.60_0.113.9~0.6.21.3", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~3.2.3_17040_28_2.6.16.60_0.113.9~0.6.21.3", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-kdump", rpm:"xen-kmp-kdump~3.2.3_17040_28_2.6.16.60_0.113.9~0.6.21.3", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-kdumppae", rpm:"xen-kmp-kdumppae~3.2.3_17040_28_2.6.16.60_0.113.9~0.6.21.3", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-smp", rpm:"xen-kmp-smp~3.2.3_17040_28_2.6.16.60_0.113.9~0.6.21.3", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-vmi", rpm:"xen-kmp-vmi~3.2.3_17040_28_2.6.16.60_0.113.9~0.6.21.3", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-vmipae", rpm:"xen-kmp-vmipae~3.2.3_17040_28_2.6.16.60_0.113.9~0.6.21.3", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~3.2.3_17040_28~0.6.21.3", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~3.2.3_17040_28~0.6.21.3", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~3.2.3_17040_28~0.6.21.3", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~3.2.3_17040_28~0.6.21.3", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-ioemu", rpm:"xen-tools-ioemu~3.2.3_17040_28~0.6.21.3", rls:"SLES10.0SP3"))) {
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
