# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123620");
  script_cve_id("CVE-2013-0153");
  script_tag(name:"creation_date", value:"2015-10-06 11:06:22 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2013-0847)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-0847");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-0847.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-348.6.1.el5, oracleasm-2.6.18-348.6.1.el5' package(s) announced via the ELSA-2013-0847 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"kernel
[2.6.18-348.6.1]
- [char] ipmi: use a tasklet for handling received messages (Tony Camuso) [953435 947732]
- [char] ipmi: do run_to_completion properly in deliver_recv_msg (Tony Camuso) [953435 947732]
- [fs] nfs4: fix locking around cl_state_owners list (Dave Wysochanski) [954296 948317]
- [fs] nfs: Fix bugs on short read (Sachin Prabhu) [952098 924011]
- [xen] AMD IOMMU: spot missing IO-APIC entries in IVRS table (Igor Mammedov) [910912 910913] {CVE-2013-0153}
- [xen] AMD, IOMMU: Make per-device interrupt remap table default (Igor Mammedov) [910912 910913] {CVE-2013-0153}
- [xen] AMD, IOMMU: Disable IOMMU if SATA Combined mode is on (Igor Mammedov) [910912 910913] {CVE-2013-0153}
- [xen] AMD, IOMMU: On creating entry clean up in remapping tables (Igor Mammedov) [910912 910913] {CVE-2013-0153}
- [xen] ACPI: acpi_table_parse() should return handler's err code (Igor Mammedov) [910912 910913] {CVE-2013-0153}
- [xen] introduce xzalloc() & Co (Igor Mammedov) [910912 910913] {CVE-2013-0153}
- [x86] fpu: fix CONFIG_PREEMPT=y corruption of FPU stack (Prarit Bhargava) [948187 731531]
- [i386] add sleazy FPU optimization (Prarit Bhargava) [948187 731531]
- [x86-64] non lazy 'sleazy' fpu implementation (Prarit Bhargava) [948187 731531]

[2.6.18-348.5.1]
- [fs] nfs: handle getattr failure during nfsv4 open (David Jeffery) [947736 906909]");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-348.6.1.el5, oracleasm-2.6.18-348.6.1.el5' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~348.6.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~348.6.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~348.6.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~348.6.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~348.6.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~348.6.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~348.6.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~348.6.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~348.6.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~348.6.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-348.6.1.el5", rpm:"ocfs2-2.6.18-348.6.1.el5~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-348.6.1.el5PAE", rpm:"ocfs2-2.6.18-348.6.1.el5PAE~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-348.6.1.el5debug", rpm:"ocfs2-2.6.18-348.6.1.el5debug~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-348.6.1.el5xen", rpm:"ocfs2-2.6.18-348.6.1.el5xen~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-348.6.1.el5", rpm:"oracleasm-2.6.18-348.6.1.el5~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-348.6.1.el5PAE", rpm:"oracleasm-2.6.18-348.6.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-348.6.1.el5debug", rpm:"oracleasm-2.6.18-348.6.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-348.6.1.el5xen", rpm:"oracleasm-2.6.18-348.6.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5"))) {
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
