# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.0156.1");
  script_cve_id("CVE-2020-26555", "CVE-2023-51779", "CVE-2023-6121", "CVE-2023-6531", "CVE-2023-6546", "CVE-2023-6606", "CVE-2023-6610", "CVE-2023-6622", "CVE-2023-6931", "CVE-2023-6932");
  script_tag(name:"creation_date", value:"2024-05-07 13:39:54 +0000 (Tue, 07 May 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-08 17:15:07 +0000 (Fri, 08 Dec 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:0156-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0156-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240156-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179610");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183045");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193285");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211162");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211226");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212584");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214747");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214823");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215237");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215696");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215885");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216057");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216559");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216776");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217036");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217217");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217250");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217602");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217692");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217790");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217801");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217933");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217938");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217946");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217947");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217980");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217981");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217982");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218056");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218139");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218184");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218234");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218253");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218258");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218335");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218357");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218447");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218515");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218559");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218569");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218659");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-January/017689.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2024:0156-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP4 kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2023-6531: Fixed a use-after-free flaw due to a race problem in the unix garbage collector's deletion of SKB races with unix_stream_read_generic()on the socket that the SKB is queued on (bsc#1218447).
- CVE-2023-6610: Fixed an out of bounds read in the SMB client when printing debug information (bsc#1217946).
- CVE-2023-51779: Fixed a use-after-free because of a bt_sock_ioctl race condition in bt_sock_recvmsg (bsc#1218559).
- CVE-2020-26555: Fixed an issue during BR/EDR PIN code pairing in the Bluetooth subsystem that would allow replay attacks (bsc#1179610 bsc#1215237).
- CVE-2023-6606: Fixed an out of bounds read in the SMB client when receiving a malformed length from a server (bsc#1217947).
- CVE-2023-6546: Fixed a race condition in the GSM 0710 tty multiplexor via the GSMIOC_SETCONF ioctl that could lead to local privilege escalation (bsc#1218335).
- CVE-2023-6931: Fixed an out of bounds write in the Performance Events subsystem when adding a new event (bsc#1218258).
- CVE-2023-6932: Fixed a use-after-free issue when receiving an IGMP query packet due to reference count mismanagement (bsc#1218253).
- CVE-2023-6622: Fixed a null pointer dereference vulnerability in nft_dynset_init() that could allow a local attacker with CAP_NET_ADMIN user privilege to trigger a denial of service (bsc#1217938).
- CVE-2023-6121: Fixed an information leak via dmesg when receiving a crafted packet in the NVMe-oF/TCP subsystem (bsc#1217250).

The following non-security bugs were fixed:

- Reviewed and added more information to README.SUSE (jsc#PED-5021).
- Enabled multibuild for kernel packages (JSC-SLE#5501, boo#1211226, bsc#1218184).
- Drop drm/bridge lt9611uxc patches that have been reverted on stable trees
- KVM: s390/mm: Properly reset no-dat (bsc#1218056).
- KVM: s390: vsie: fix wrong VIR 37 when MSO is used (bsc#1217933).
- KVM: x86: Mask LVTPC when handling a PMI (jsc#PED-7322).
- NFS: Fix O_DIRECT locking issues (bsc#1211162).
- NFS: Fix a few more clear_bit() instances that need release semantics (bsc#1211162).
- NFS: Fix a potential data corruption (bsc#1211162).
- NFS: Fix a use after free in nfs_direct_join_group() (bsc#1211162).
- NFS: Fix error handling for O_DIRECT write scheduling (bsc#1211162).
- NFS: More O_DIRECT accounting fixes for error paths (bsc#1211162).
- NFS: More fixes for nfs_direct_write_reschedule_io() (bsc#1211162).
- NFS: Use the correct commit info in nfs_join_page_group() (bsc#1211162).
- NLM: Defend against file_lock changes after vfs_test_lock() (bsc#1217692).
- Updated SPI patches for NVIDIA Grace enablement (bsc#1212584 jsc#PED-3459)
- block: fix revalidate performance regression (bsc#1216057).
- bpf: Adjust insufficient default bpf_jit_limit (bsc#1218234).
- ceph: fix incorrect revoked caps assert in ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP4.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.14.21~150400.24.103.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.14.21~150400.24.103.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.14.21~150400.24.103.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.14.21~150400.24.103.1.150400.24.48.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.14.21~150400.24.103.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.14.21~150400.24.103.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.14.21~150400.24.103.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.14.21~150400.24.103.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.14.21~150400.24.103.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.14.21~150400.24.103.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.14.21~150400.24.103.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.14.21~150400.24.103.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.14.21~150400.24.103.1", rls:"SLES15.0SP4"))) {
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
