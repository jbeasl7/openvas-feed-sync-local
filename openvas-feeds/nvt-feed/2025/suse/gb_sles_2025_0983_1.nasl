# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.0983.1");
  script_cve_id("CVE-2021-47633", "CVE-2022-1048", "CVE-2022-3303", "CVE-2022-49272", "CVE-2022-49288", "CVE-2022-49291", "CVE-2022-49545", "CVE-2022-49733", "CVE-2024-56658", "CVE-2024-57996", "CVE-2025-21718", "CVE-2025-21772");
  script_tag(name:"creation_date", value:"2025-03-24 04:07:40 +0000 (Mon, 24 Mar 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-06 19:29:49 +0000 (Mon, 06 Jan 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:0983-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0983-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250983-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197331");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203769");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235441");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237768");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238271");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238272");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238454");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238705");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238911");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239073");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239076");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-March/020579.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2025:0983-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP4 kernel was updated to receive various security bugfixes.

The following security bugs were fixed:

- CVE-2021-47633: ath5k: fix OOB in ath5k_eeprom_read_pcal_info_5111 (bsc#1237768).
- CVE-2022-49545: ALSA: usb-audio: Cancel pending work at closing a MIDI substream (bsc#1238729).
- CVE-2024-56658: net: defer final 'struct net' free in netns dismantle (bsc#1235441).
- CVE-2024-57996: net_sched: sch_sfq: do not allow 1 packet limit (bsc#1239076).
- CVE-2025-21718: net: rose: fix timer races against user threads (bsc#1239073).
- CVE-2025-21772: partitions: mac: fix handling of bogus partition table (bsc#1238911).");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~108.180.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~108.180.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~108.180.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~108.180.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~108.180.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~108.180.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~108.180.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~108.180.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~108.180.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~108.180.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~108.180.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~108.180.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~108.180.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~108.180.1", rls:"SLES11.0SP4"))) {
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
