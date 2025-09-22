# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123935");
  script_cve_id("CVE-2012-1583");
  script_tag(name:"creation_date", value:"2015-10-06 11:10:31 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2012-0480)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-0480");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-0480.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-308.4.1.el5, oracleasm-2.6.18-308.4.1.el5' package(s) announced via the ELSA-2012-0480 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.18-308.4.1.el5]
- [net] ipv6: fix skb double free in xfrm6_tunnel (Jiri Benc) [752305 743375] {CVE-2012-1583}

[2.6.18-308.3.1.el5]
- [net] be2net: cancel be_worker during EEH recovery (Ivan Vecera) [805462 773735]
- [net] be2net: add vlan/rx-mode/flow-control config to be_setup (Ivan Vecera) [805462 773735]
- [x86] disable TSC synchronization when using kvmclock (Marcelo Tosatti) [805460 799170]
- [fs] vfs: fix LOOKUP_DIRECTORY not propagated to managed_dentry (Ian Kent) [801726 798809]
- [fs] vfs: fix d_instantiate_unique (Ian Kent) [801726 798809]
- [fs] nfs: allow high priority COMMITs to bypass inode commit lock (Jeff Layton) [799941 773777]
- [fs] nfs: don't skip COMMITs if system under is mem pressure (Jeff Layton) [799941 773777]
- [scsi] qla2xxx: Read the HCCR register to flush any PCIe writes (Chad Dupuis) [798748 772192]
- [scsi] qla2xxx: Complete mbox cmd timeout before next reset cycle (Chad Dupuis) [798748 772192]
- [s390] qdio: wrong buffers-used counter for ERROR buffers (Hendrik Brueckner) [801724 790840]
- [net] bridge: Reset IPCB when entering IP stack (Herbert Xu) [804721 749813]
- [fs] procfs: add hidepid= and gid= mount options (Jerome Marchand) [770649 770650]
- [fs] procfs: parse mount options (Jerome Marchand) [770649 770650]

[2.6.18-308.2.1.el5]
- [fs] nfs: nfs_fhget should wait on I_NEW instead of I_LOCK (Sachin Prabhu) [795664 785062]");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-308.4.1.el5, oracleasm-2.6.18-308.4.1.el5' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~308.4.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~308.4.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~308.4.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~308.4.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~308.4.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~308.4.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~308.4.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~308.4.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~308.4.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~308.4.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-308.4.1.el5", rpm:"ocfs2-2.6.18-308.4.1.el5~1.4.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-308.4.1.el5PAE", rpm:"ocfs2-2.6.18-308.4.1.el5PAE~1.4.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-308.4.1.el5debug", rpm:"ocfs2-2.6.18-308.4.1.el5debug~1.4.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-308.4.1.el5xen", rpm:"ocfs2-2.6.18-308.4.1.el5xen~1.4.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-308.4.1.el5", rpm:"oracleasm-2.6.18-308.4.1.el5~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-308.4.1.el5PAE", rpm:"oracleasm-2.6.18-308.4.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-308.4.1.el5debug", rpm:"oracleasm-2.6.18-308.4.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-308.4.1.el5xen", rpm:"oracleasm-2.6.18-308.4.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5"))) {
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
