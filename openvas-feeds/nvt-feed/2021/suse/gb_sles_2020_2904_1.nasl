# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.2904.1");
  script_cve_id("CVE-2019-25643", "CVE-2020-0404", "CVE-2020-0427", "CVE-2020-0431", "CVE-2020-0432", "CVE-2020-14381", "CVE-2020-14390", "CVE-2020-25212", "CVE-2020-25284", "CVE-2020-25641", "CVE-2020-25643", "CVE-2020-26088");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-08 16:00:59 +0000 (Tue, 08 Dec 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:2904-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:2904-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20202904-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094244");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112178");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113956");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154366");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163524");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1167527");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168468");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1169972");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171675");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171688");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171742");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173115");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174354");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174899");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175228");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175528");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175716");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175749");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175882");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176011");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176022");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176235");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176242");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176278");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176316");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176317");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176318");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176319");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176320");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176321");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176381");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176423");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176482");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176507");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176536");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176544");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176545");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176546");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176548");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176659");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176698");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176699");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176700");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176721");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176722");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176725");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176732");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176788");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176789");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176869");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176877");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176935");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176950");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176962");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176966");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176990");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177030");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177041");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177042");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177043");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177044");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177121");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177206");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177258");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177291");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177293");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177294");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177295");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177296");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-October/007544.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:2904-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2020-26088: Fixed an improper CAP_NET_RAW check in NFC socket creation could have been used by local attackers to create raw sockets, bypassing security mechanisms (bsc#1176990).
- CVE-2020-14390: Fixed an out-of-bounds memory write leading to memory corruption or a denial of service when changing screen size (bnc#1176235).
- CVE-2020-0432: Fixed an out of bounds write due to an integer overflow (bsc#1176721).
- CVE-2020-0427: Fixed an out of bounds read due to a use after free (bsc#1176725).
- CVE-2020-0431: Fixed an out of bounds write due to a missing bounds check (bsc#1176722).
- CVE-2020-0404: Fixed a linked list corruption due to an unusual root cause (bsc#1176423).
- CVE-2020-25212: Fixed getxattr kernel panic and memory overflow (bsc#1176381).
- CVE-2020-25284: Fixed an incomplete permission checking for access to rbd devices, which could have been leveraged by local attackers to map or unmap rbd block devices (bsc#1176482).
- CVE-2020-14381: Fixed requeue paths such that filp was valid when dropping the references (bsc#1176011).
- CVE-2019-25643: Fixed an improper input validation in ppp_cp_parse_cr function which could have led to memory corruption and read overflow (bsc#1177206).
- CVE-2020-25641: Fixed ann issue where length bvec was causing softlockups (bsc#1177121).

The following non-security bugs were fixed:

- 9p: Fix memory leak in v9fs_mount (git-fixes).
- ACPI: EC: Reference count query handlers under lock (git-fixes).
- airo: Add missing CAP_NET_ADMIN check in AIROOLDIOCTL/SIOCDEVPRIVATE (git-fixes).
- airo: Fix possible info leak in AIROOLDIOCTL/SIOCDEVPRIVATE (git-fixes).
- airo: Fix read overflows sending packets (git-fixes).
- ALSA: asihpi: fix iounmap in error handler (git-fixes).
- ALSA: firewire-digi00x: exclude Avid Adrenaline from detection (git-fixes).
- ALSA: firewire-tascam: exclude Tascam FE-8 from detection (git-fixes).
- ALSA: hda: Fix 2 channel swapping for Tegra (git-fixes).
- ALSA: hda: fix a runtime pm issue in SOF when integrated GPU is disabled (git-fixes).
- ALSA: hda/realtek: Add quirk for Samsung Galaxy Book Ion NT950XCJ-X716A (git-fixes).
- ALSA: hda/realtek - Improved routing for Thinkpad X1 7th/8th Gen (git-fixes).
- altera-stapl: altera_get_note: prevent write beyond end of 'key' (git-fixes).
- ar5523: Add USB ID of SMCWUSBT-G2 wireless adapter (git-fixes).
- arm64: KVM: Do not generate UNDEF when LORegion feature is present (jsc#SLE-4084).
- arm64: KVM: regmap: Fix unexpected switch fall-through (jsc#SLE-4084).
- asm-generic: fix -Wtype-limits compiler warnings (bsc#1112178).
- ASoC: kirkwood: fix IRQ error handling (git-fixes).
- ASoC: tegra: Fix reference count leaks (git-fixes).
- ath10k: fix array out-of-bounds access (git-fixes).
- ath10k: fix memory leak for tpc_stats_final ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.41.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.41.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.41.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.41.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.41.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.41.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.41.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.41.1", rls:"SLES12.0SP5"))) {
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
