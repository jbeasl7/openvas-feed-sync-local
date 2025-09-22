# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123869");
  script_cve_id("CVE-2012-3375");
  script_tag(name:"creation_date", value:"2015-10-06 11:09:38 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2012-1061)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-1061");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-1061.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-308.11.1.el5, oracleasm-2.6.18-308.11.1.el5' package(s) announced via the ELSA-2012-1061 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.18-308.11.1.el5]
- [net] ixgbe: remove flow director stats (Andy Gospodarek) [832169 830226]
- [net] ixgbe: fix default return value for ixgbe_cache_ring_fdir (Andy Gospodarek) [832169 830226]
- [net] ixgbe: reverting setup redirection table for multiple packet buffers (Andy Gospodarek) [832169 830226]

[2.6.18-308.10.1.el5]
- [xen] x86_64: check address on trap handlers or guest callbacks (Paolo Bonzini) [813430 813431] {CVE-2012-0217}
- [xen] x86_64: Do not execute sysret with a non-canonical return address (Paolo Bonzini) [813430 813431] {CVE-2012-0217}
- [xen] x86: prevent hv boot on AMD CPUs with Erratum 121 (Laszlo Ersek) [824969 824970] {CVE-2012-2934}
- [scsi] qla2xxx: Use ha->pdev->revision in 4Gbps MSI-X check. (Chad Dupuis) [816373 800653]
- [fs] sunrpc: do array overrun check in svc_recv before page alloc (J. Bruce Fields) [820358 814626]
- [fs] knfsd: fix an NFSD bug with full size non-page-aligned reads (J. Bruce Fields) [820358 814626]
- [fs] sunrpc: fix oops due to overrunning server's page array (J. Bruce Fields) [820358 814626]
- [fs] epoll: clear the tfile_check_list on -ELOOP (Jason Baron) [829670 817131]
- [x86_64] sched: Avoid unnecessary overflow in sched_clock (Prarit Bhargava) [824654 818787]
- [net] sunrpc: Don't use list_for_each_entry_safe in rpc_wake_up (Steve Dickson) [817571 809937]
- [s390] qeth: add missing wake_up call (Hendrik Brueckner) [829059 790900]

[2.6.18-308.9.1.el5]
- [fs] jbd: clear b_modified before moving the jh to a different transaction (Josef Bacik) [827205 563247]");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-308.11.1.el5, oracleasm-2.6.18-308.11.1.el5' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~308.11.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~308.11.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~308.11.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~308.11.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~308.11.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~308.11.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~308.11.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~308.11.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~308.11.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~308.11.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-308.11.1.el5", rpm:"ocfs2-2.6.18-308.11.1.el5~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-308.11.1.el5PAE", rpm:"ocfs2-2.6.18-308.11.1.el5PAE~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-308.11.1.el5debug", rpm:"ocfs2-2.6.18-308.11.1.el5debug~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-308.11.1.el5xen", rpm:"ocfs2-2.6.18-308.11.1.el5xen~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-308.11.1.el5", rpm:"oracleasm-2.6.18-308.11.1.el5~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-308.11.1.el5PAE", rpm:"oracleasm-2.6.18-308.11.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-308.11.1.el5debug", rpm:"oracleasm-2.6.18-308.11.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-308.11.1.el5xen", rpm:"oracleasm-2.6.18-308.11.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5"))) {
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
