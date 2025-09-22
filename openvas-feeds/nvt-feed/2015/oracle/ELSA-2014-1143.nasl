# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123320");
  script_cve_id("CVE-2014-3917");
  script_tag(name:"creation_date", value:"2015-10-06 11:02:14 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2014-1143)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-1143");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-1143.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-371.12.1.el5, oracleasm-2.6.18-371.12.1.el5' package(s) announced via the ELSA-2014-1143 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"kernel
[2.6.18-371.12.1]
- [audit] auditsc: audit_krule mask accesses need bounds checking (Denys Vlasenko) [1102702 1102703] {CVE-2014-3917}
- [mm] writeback: Fix hang when low on memory due to NFS traffic (Larry Woodman) [1125246 1080194]
- [net] tg3: Fix Read DMA workaround for 5719 A0 (Ivan Vecera) [1121017 924590]
- [fs] jbd: don't wake kjournald unnecessarily (Denys Vlasenko) [1116027 1081785]
- [fs] jbd: don't wait (forever) for stale tid caused by wraparound (Denys Vlasenko) [1116027 1081785]
- [fs] ext4: fix waiting and sending of barrier in ext4_sync_file() (Denys Vlasenko) [1116027 1081785]
- [fs] jbd2: Add function jbd2_trans_will_send_data_barrier() (Denys Vlasenko) [1116027 1081785]
- [fs] jbd2: fix sending of data flush on journal commit (Denys Vlasenko) [1116027 1081785]
- [fs] ext4, jbd2: Add barriers for file systems with ext journals (Denys Vlasenko) [1116027 1081785]
- [fs] jbd: fix fsync() tid wraparound bug (Denys Vlasenko) [1116027 1081785]
- [fs] ext4: fix fdatasync() for files with only i_size changes (Eric Sandeen) [1117665 1102768]");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-371.12.1.el5, oracleasm-2.6.18-371.12.1.el5' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~371.12.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~371.12.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~371.12.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~371.12.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~371.12.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~371.12.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~371.12.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~371.12.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~371.12.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~371.12.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-371.12.1.el5", rpm:"ocfs2-2.6.18-371.12.1.el5~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-371.12.1.el5PAE", rpm:"ocfs2-2.6.18-371.12.1.el5PAE~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-371.12.1.el5debug", rpm:"ocfs2-2.6.18-371.12.1.el5debug~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-371.12.1.el5xen", rpm:"ocfs2-2.6.18-371.12.1.el5xen~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-371.12.1.el5", rpm:"oracleasm-2.6.18-371.12.1.el5~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-371.12.1.el5PAE", rpm:"oracleasm-2.6.18-371.12.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-371.12.1.el5debug", rpm:"oracleasm-2.6.18-371.12.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-371.12.1.el5xen", rpm:"oracleasm-2.6.18-371.12.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5"))) {
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
