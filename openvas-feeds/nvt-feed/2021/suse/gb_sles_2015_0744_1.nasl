# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0744.1");
  script_cve_id("CVE-2013-3495", "CVE-2014-3615", "CVE-2014-5146", "CVE-2014-5149", "CVE-2014-9065", "CVE-2014-9066", "CVE-2015-0361", "CVE-2015-2044", "CVE-2015-2045", "CVE-2015-2151");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:13 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0744-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0744-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150744-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Xen' package(s) announced via the SUSE-SU-2015:0744-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Virtualization service XEN was updated to fix various bugs and security issues.
The following security issues have been fixed:
XSA-125: Long latency MMIO mapping operations were not preemptible.
CVE-2015-2151: XSA-123: Instructions with register operands ignored eventual segment overrides encoded for them. Due to an insufficiently conditional assignment such a bogus segment override could have,
however, corrupted a pointer used subsequently to store the result of the instruction.
CVE-2015-2045: XSA-122: The code handling certain sub-operations of the HYPERVISOR_xen_version hypercall failed to fully initialize all fields of structures subsequently copied back to guest memory. Due to this hypervisor stack contents were copied into the destination of the operation, thus becoming visible to the guest.
CVE-2015-2044: XSA-121: Emulation routines in the hypervisor dealing with certain system devices checked whether the access size by the guest is a supported one. When the access size is unsupported these routines failed to set the data to be returned to the guest for read accesses,
so that hypervisor stack contents were copied into the destination of the operation, thus becoming visible to the guest.
Security Issues:
CVE-2013-3495 CVE-2014-5146 CVE-2014-5149 CVE-2014-3615 CVE-2014-9065 CVE-2014-9066 CVE-2015-0361 CVE-2015-2044 CVE-2015-2045");

  script_tag(name:"affected", value:"'Xen' package(s) on SUSE Linux Enterprise Server 10-SP4.");

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

if(release == "SLES10.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~3.2.3_17040_46~0.13.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~3.2.3_17040_46~0.13.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~3.2.3_17040_46~0.13.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-pdf", rpm:"xen-doc-pdf~3.2.3_17040_46~0.13.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-ps", rpm:"xen-doc-ps~3.2.3_17040_46~0.13.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-bigsmp", rpm:"xen-kmp-bigsmp~3.2.3_17040_46_2.6.16.60_0.107.36~0.13.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-debug", rpm:"xen-kmp-debug~3.2.3_17040_46_2.6.16.60_0.107.36~0.13.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~3.2.3_17040_46_2.6.16.60_0.107.36~0.13.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-kdump", rpm:"xen-kmp-kdump~3.2.3_17040_46_2.6.16.60_0.107.36~0.13.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-kdumppae", rpm:"xen-kmp-kdumppae~3.2.3_17040_46_2.6.16.60_0.107.36~0.13.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-smp", rpm:"xen-kmp-smp~3.2.3_17040_46_2.6.16.60_0.107.36~0.13.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-vmi", rpm:"xen-kmp-vmi~3.2.3_17040_46_2.6.16.60_0.107.36~0.13.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-vmipae", rpm:"xen-kmp-vmipae~3.2.3_17040_46_2.6.16.60_0.107.36~0.13.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~3.2.3_17040_46~0.13.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~3.2.3_17040_46~0.13.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~3.2.3_17040_46~0.13.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~3.2.3_17040_46~0.13.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-ioemu", rpm:"xen-tools-ioemu~3.2.3_17040_46~0.13.1", rls:"SLES10.0SP4"))) {
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
