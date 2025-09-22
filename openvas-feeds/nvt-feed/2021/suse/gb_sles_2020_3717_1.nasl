# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3717.1");
  script_cve_id("CVE-2020-15436", "CVE-2020-15437", "CVE-2020-25668", "CVE-2020-25669", "CVE-2020-25704", "CVE-2020-25705", "CVE-2020-27777", "CVE-2020-28915", "CVE-2020-28974", "CVE-2020-29371");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-04 11:55:41 +0000 (Fri, 04 Jun 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3717-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3717-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203717-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050549");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1067665");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112178");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158775");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170139");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170630");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172542");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172873");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174726");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175306");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175721");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175916");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176109");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176855");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176983");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177304");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177397");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177703");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177805");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177808");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177809");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177819");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177820");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178123");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178182");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178393");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178589");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178607");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178669");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178686");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178765");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178782");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178838");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178853");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178854");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178886");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178897");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178940");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178962");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179107");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179140");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179141");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179211");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179213");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179259");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179424");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179426");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179427");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179429");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/927455");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-December/007940.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:3717-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2020-15436: Fixed a use after free vulnerability in fs/block_dev.c which could have allowed local users to gain privileges or cause a denial of service (bsc#1179141).
- CVE-2020-15437: Fixed a null pointer dereference which could have allowed local users to cause a denial of service(bsc#1179140).
- CVE-2020-25668: Fixed a concurrency use-after-free in con_font_op (bsc#1178123).
- CVE-2020-25669: Fixed a use-after-free read in sunkbd_reinit() (bsc#1178182).
- CVE-2020-25704: Fixed a leak in perf_event_parse_addr_filter() (bsc#1178393).
- CVE-2020-27777: Restrict RTAS requests from userspace (bsc#1179107)
- CVE-2020-28915: Fixed a buffer over-read in the fbcon code which could have been used by local attackers to read kernel memory (bsc#1178886).
- CVE-2020-28974: Fixed a slab-out-of-bounds read in fbcon which could have been used by local attackers to read privileged information or potentially crash the kernel (bsc#1178589).
- CVE-2020-29371: Fixed uninitialized memory leaks to userspace (bsc#1179429).
- CVE-2020-25705: Fixed an issue which could have allowed to quickly scan open UDP ports. This flaw allowed an off-path remote user to effectively bypassing source port UDP randomization (bsc#1175721).

The following non-security bugs were fixed:

- 9P: Cast to loff_t before multiplying (git-fixes).
- ACPI: GED: fix -Wformat (git-fixes).
- ACPI: NFIT: Fix comparison to '-ENXIO' (git-fixes).
- ALSA: ctl: fix error path at adding user-defined element set (git-fixes).
- ALSA: firewire: Clean up a locking issue in copy_resp_to_buf() (git-fixes).
- ALSA: hda - Fix the return value if cb func is already registered (git-fixes).
- ALSA: hda: prevent undefined shift in snd_hdac_ext_bus_get_link() (git-fixes).
- ALSA: mixart: Fix mutex deadlock (git-fixes).
- arm64: KVM: Fix system register enumeration (bsc#1174726).
- arm/arm64: KVM: Add PSCI version selection API (bsc#1174726).
- ASoC: qcom: lpass-platform: Fix memory leak (git-fixes).
- ath10k: Acquire tx_lock in tx error paths (git-fixes).
- batman-adv: set .owner to THIS_MODULE (git-fixes).
- Bluetooth: btusb: Fix and detect most of the Chinese Bluetooth controllers (git-fixes).
- Bluetooth: hci_bcm: fix freeing not-requested IRQ (git-fixes).
- bpf: Zero-fill re-used per-cpu map element (git-fixes).
- btrfs: account ticket size at add/delete time (bsc#1178897).
- btrfs: add helper to obtain number of devices with ongoing dev-replace (bsc#1178897).
- btrfs: check rw_devices, not num_devices for balance (bsc#1178897).
- btrfs: do not delete mismatched root refs (bsc#1178962).
- btrfs: fix btrfs_calc_reclaim_metadata_size calculation (bsc#1178897).
- btrfs: fix force usage in inc_block_group_ro (bsc#1178897).
- btrfs: fix invalid removal of root ref (bsc#1178962).
- btrfs: fix reclaim counter ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.54.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.54.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.54.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.54.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.54.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.54.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.54.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.54.1", rls:"SLES12.0SP5"))) {
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
