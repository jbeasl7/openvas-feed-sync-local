# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.01627.1");
  script_cve_id("CVE-2021-47671", "CVE-2022-49741", "CVE-2024-46784", "CVE-2025-21726", "CVE-2025-21785", "CVE-2025-21791", "CVE-2025-21812", "CVE-2025-21886", "CVE-2025-22004", "CVE-2025-22020", "CVE-2025-22045", "CVE-2025-22055", "CVE-2025-22097");
  script_tag(name:"creation_date", value:"2025-05-22 12:07:17 +0000 (Thu, 22 May 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-06 16:45:15 +0000 (Tue, 06 May 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:01627-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:01627-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202501627-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201855");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230771");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238471");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238512");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238747");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238865");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239968");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240188");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240195");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240553");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240747");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240835");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241280");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241371");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241421");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241433");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241541");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-May/039279.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2025:01627-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP4 kernel was updated to receive various security bugfixes.

The following security bugs were fixed:

- CVE-2025-21726: padata: avoid UAF for reorder_work (bsc#1238865).
- CVE-2025-21785: arm64: cacheinfo: Avoid out-of-bounds write to cacheinfo array (bsc#1238747).
- CVE-2025-21791: vrf: use RCU protection in l3mdev_l3_out() (bsc#1238512).
- CVE-2025-21812: ax25: rcu protect dev->ax25_ptr (bsc#1238471).
- CVE-2025-22004: net: atm: fix use after free in lec_send() (bsc#1240835).
- CVE-2025-22020: memstick: rtsx_usb_ms: Fix slab-use-after-free in rtsx_usb_ms_drv_remove (bsc#1241280).
- CVE-2025-22045: x86/mm: Fix flush_tlb_range() when used for zapping normal PMDs (bsc#1241433).
- CVE-2025-22055: net: fix geneve_opt length integer overflow (bsc#1241371).
- CVE-2025-22097: drm/vkms: Fix use after free and double free on init error (bsc#1241541).

The following non-security bugs were fixed:

- scsi: smartpqi: Add ctrl ready timeout module parameter (jsc#PED-1557, bsc#1201855, bsc#1240553).");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.14.21~150400.24.164.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.14.21~150400.24.164.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.14.21~150400.24.164.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.14.21~150400.24.164.1.150400.24.82.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.14.21~150400.24.164.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.14.21~150400.24.164.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.14.21~150400.24.164.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.14.21~150400.24.164.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.14.21~150400.24.164.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.14.21~150400.24.164.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.14.21~150400.24.164.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.14.21~150400.24.164.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.14.21~150400.24.164.1", rls:"SLES15.0SP4"))) {
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
