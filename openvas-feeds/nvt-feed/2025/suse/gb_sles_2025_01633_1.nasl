# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.01633.1");
  script_cve_id("CVE-2020-36789", "CVE-2021-47163", "CVE-2021-47668", "CVE-2021-47669", "CVE-2021-47670", "CVE-2022-49111", "CVE-2023-0179", "CVE-2023-53026", "CVE-2023-53033", "CVE-2024-56642", "CVE-2024-56661", "CVE-2025-21726", "CVE-2025-21785", "CVE-2025-21791", "CVE-2025-22004", "CVE-2025-22020", "CVE-2025-22055");
  script_tag(name:"creation_date", value:"2025-05-22 12:07:17 +0000 (Thu, 22 May 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-06 16:45:15 +0000 (Tue, 06 May 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:01633-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:01633-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202501633-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207034");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221980");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234931");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235433");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237984");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238512");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238747");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238865");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240210");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240308");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240835");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241280");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241371");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241404");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241405");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241407");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241408");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-May/039273.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2025:01633-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2022-49111: Bluetooth: Fix use after free in hci_send_acl (bsc#1237984).
- CVE-2025-21726: padata: avoid UAF for reorder_work (bsc#1238865).
- CVE-2025-21785: arm64: cacheinfo: Avoid out-of-bounds write to cacheinfo array (bsc#1238747).
- CVE-2025-21791: vrf: use RCU protection in l3mdev_l3_out() (bsc#1238512).
- CVE-2025-22004: net: atm: fix use after free in lec_send() (bsc#1240835).
- CVE-2025-22020: memstick: rtsx_usb_ms: Fix slab-use-after-free in rtsx_usb_ms_drv_remove (bsc#1241280).
- CVE-2025-22055: net: fix geneve_opt length integer overflow (bsc#1241371).");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP3.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.3.18~150300.59.204.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.3.18~150300.59.204.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~150300.59.204.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~150300.59.204.1.150300.18.122.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~150300.59.204.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~150300.59.204.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~150300.59.204.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~150300.59.204.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~150300.59.204.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~150300.59.204.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~150300.59.204.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~150300.59.204.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~150300.59.204.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.3.18~150300.59.204.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.3.18~150300.59.204.1", rls:"SLES15.0SP3"))) {
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
