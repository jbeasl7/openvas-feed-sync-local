# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.3547.1");
  script_cve_id("CVE-2022-48911", "CVE-2022-48923", "CVE-2022-48944", "CVE-2022-48945", "CVE-2024-41087", "CVE-2024-42301", "CVE-2024-44946", "CVE-2024-45021", "CVE-2024-46674", "CVE-2024-46774");
  script_tag(name:"creation_date", value:"2025-02-13 14:53:48 +0000 (Thu, 13 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-13 16:51:45 +0000 (Fri, 13 Sep 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:3547-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3547-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243547-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216223");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223958");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225272");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227487");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228466");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229407");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229633");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229662");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229947");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230015");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230398");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230434");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230507");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230767");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231016");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-October/037167.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2024:3547-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP4 kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2022-48911: kabi: add __nf_queue_get_refs() for kabi compliance. (bsc#1229633).
- CVE-2022-48923: btrfs: prevent copying too big compressed lzo segment (bsc#1229662)
- CVE-2024-41087: Fix double free on error (bsc#1228466).
- CVE-2024-42301: Fix the array out-of-bounds risk (bsc#1229407).
- CVE-2024-44946: kcm: Serialise kcm_sendmsg() for the same socket (bsc#1230015).
- CVE-2024-45021: memcg_write_event_control(): fix a user-triggerable oops (bsc#1230434).
- CVE-2024-46674: usb: dwc3: st: fix probed platform device ref count on probe error path (bsc#1230507).

The following non-security bugs were fixed:

- blk-mq: add helper for checking if one CPU is mapped to specified hctx (bsc#1223600).
- blk-mq: do not schedule block kworker on isolated CPUs (bsc#1223600).
- kabi: add __nf_queue_get_refs() for kabi compliance.
- scsi: ibmvfc: Add max_sectors module parameter (bsc#1216223).
- scsi: smartpqi: Expose SAS address for SATA drives (bsc#1223958).
- SUNRPC: avoid soft lockup when transmitting UDP to reachable server (bsc#1225272 bsc#1231016).");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.14.21~150400.24.136.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.14.21~150400.24.136.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.14.21~150400.24.136.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.14.21~150400.24.136.1.150400.24.66.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.14.21~150400.24.136.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.14.21~150400.24.136.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.14.21~150400.24.136.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.14.21~150400.24.136.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.14.21~150400.24.136.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.14.21~150400.24.136.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.14.21~150400.24.136.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.14.21~150400.24.136.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.14.21~150400.24.136.1", rls:"SLES15.0SP4"))) {
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
