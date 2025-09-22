# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.0407.1");
  script_cve_id("CVE-2022-3564", "CVE-2022-4662", "CVE-2022-47929", "CVE-2023-23454");
  script_tag(name:"creation_date", value:"2023-02-15 04:21:53 +0000 (Wed, 15 Feb 2023)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-13 18:31:32 +0000 (Tue, 13 Dec 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:0407-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0407-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20230407-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203693");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205149");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206073");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206664");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206677");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206784");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207036");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207237");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2023-February/013758.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2023:0407-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP4 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2022-47929: Fixed NULL pointer dereference bug in the traffic control subsystem (bnc#1207237).
- CVE-2023-23454: Fixed denial or service in cbq_classify in net/sched/sch_cbq.c (bnc#1207036).
- CVE-2022-4662: Fixed incorrect access control in the USB core subsystem that could lead a local user to crash the system (bnc#1206664).
- CVE-2022-3564: Fixed use-after-free in l2cap_core.c of the Bluetooth component (bnc#1206073).

The following non-security bugs were fixed:

- Added support for enabling livepatching related packages on -RT (jsc#PED-1706).
- Added suse-kernel-rpm-scriptlets to kmp buildreqs (boo#1205149).
- Reverted 'constraints: increase disk space for all architectures' (bsc#1203693).
- HID: betop: check shape of output reports (bsc#1207186).
- HID: betop: fix slab-out-of-bounds Write in betop_probe (bsc#1207186).
- HID: check empty report_list in hid_validate_values() (bsc#1206784).
- net: sched: atm: dont intepret cls results when asked to drop (bsc#1207036).
- net: sched: cbq: dont intepret cls results when asked to drop (bsc#1207036).
- sctp: fail if no bound addresses can be used for a given scope (bsc#1206677).");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP4.");

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

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~95.117.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~95.117.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~95.117.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~95.117.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~95.117.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~95.117.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~95.117.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~95.117.1", rls:"SLES12.0SP4"))) {
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
