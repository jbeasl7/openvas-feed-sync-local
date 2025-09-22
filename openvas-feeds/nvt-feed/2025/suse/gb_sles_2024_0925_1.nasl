# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.0925.1");
  script_cve_id("CVE-2019-25162", "CVE-2020-36777", "CVE-2020-36784", "CVE-2021-33200", "CVE-2021-46906", "CVE-2021-46915", "CVE-2021-46921", "CVE-2021-46924", "CVE-2021-46929", "CVE-2021-46932", "CVE-2021-46953", "CVE-2021-46974", "CVE-2021-46991", "CVE-2021-46992", "CVE-2021-47013", "CVE-2021-47054", "CVE-2021-47076", "CVE-2021-47077", "CVE-2021-47078", "CVE-2022-20154", "CVE-2022-48627", "CVE-2023-28746", "CVE-2023-35827", "CVE-2023-46343", "CVE-2023-52340", "CVE-2023-52429", "CVE-2023-52443", "CVE-2023-52445", "CVE-2023-52449", "CVE-2023-52451", "CVE-2023-52464", "CVE-2023-52475", "CVE-2023-52478", "CVE-2023-52482", "CVE-2023-52502", "CVE-2023-52530", "CVE-2023-52531", "CVE-2023-52532", "CVE-2023-52574", "CVE-2023-52597", "CVE-2023-52605", "CVE-2024-0607", "CVE-2024-1151", "CVE-2024-23849", "CVE-2024-23851", "CVE-2024-26585", "CVE-2024-26595", "CVE-2024-26600", "CVE-2024-26622");
  script_tag(name:"creation_date", value:"2025-02-13 14:53:48 +0000 (Thu, 13 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-11 17:36:15 +0000 (Wed, 11 Dec 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:0925-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0925-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240925-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050549");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186484");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1200599");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213456");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218450");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218527");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218915");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219127");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219146");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219295");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219653");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219827");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219835");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220187");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220238");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220240");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220241");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220250");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220330");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220340");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220344");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220409");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220421");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220436");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220444");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220459");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220468");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220482");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220526");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220570");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220575");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220599");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220607");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220613");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220638");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220641");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220649");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220700");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220767");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220796");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220825");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220831");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220845");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220860");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220861");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220863");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220870");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220930");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220931");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220932");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220957");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221039");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221040");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221287");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-March/018205.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2024:0925-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security bugfixes.

The following security bugs were fixed:

- CVE-2021-47078: Fixed a bug by clearing all QP fields if creation failed (bsc#1220863)
- CVE-2021-47076: Fixed a bug by returning CQE error if invalid lkey was supplied (bsc#1220860)
- CVE-2023-52605: Fixed a NULL pointer dereference check (bsc#1221039)
- CVE-2023-52597: Fixed a setting of fpc register in KVM (bsc#1221040).
- CVE-2023-52574: Fixed a bug by hiding new member header_ops (bsc#1220870).
- CVE-2023-52482: Fixed a bug by adding SRSO mitigation for Hygon processors (bsc#1220735).
- CVE-2022-48627: Fixed a memory overlapping when deleting chars in the buffer (bsc#1220845).
- CVE-2023-28746: Fixed Register File Data Sampling (bsc#1213456).
- CVE-2021-47077: Fixed a NULL pointer dereference when in shost_data (bsc#1220861).
- CVE-2023-35827: Fixed a use-after-free issue in ravb_tx_timeout_work (bsc#1212514).
- CVE-2023-52532: Fixed a bug in TX CQE error handling (bsc#1220932).
- CVE-2023-52530: Fixed a potential key use-after-free in wifi mac80211 (bsc#1220930).
- CVE-2023-52531: Fixed a memory corruption issue in iwlwifi (bsc#1220931).
- CVE-2023-52502: Fixed a race condition in nfc_llcp_sock_get and nfc_llcp_sock_get_sn (bsc#1220831).
- CVE-2024-26585: Fixed race between tx work scheduling and socket close (bsc#1220187).
- CVE-2023-52340: Fixed ICMPv6 'Packet Too Big' packets force a DoS of the Linux kernel by forcing 100% CPU (bsc#1219295).
- CVE-2024-0607: Fixed 64-bit load issue in nft_byteorder_eval (bsc#1218915).
- CVE-2024-26622: Fixed UAF write bug in tomoyo_write_control (bsc#1220825).
- CVE-2021-46921: Fixed ordering in queued_write_lock_slowpath (bsc#1220468).
- CVE-2021-46932: Fixed missing work initialization before device registration (bsc#1220444)
- CVE-2023-52451: Fixed access beyond end of drmem array (bsc#1220250).
- CVE-2021-46953: Fixed a corruption in interrupt mappings on watchdow probe failure (bsc#1220599).
- CVE-2023-52449: Fixed gluebi NULL pointer dereference caused by ftl notifier (bsc#1220238).
- CVE-2023-52475: Fixed use-after-free in powermate_config_complete (bsc#1220649)
- CVE-2023-52478: Fixed kernel crash on receiver USB disconnect (bsc#1220796)
- CVE-2019-25162: Fixed a potential use after free (bsc#1220409).
- CVE-2020-36784: Fixed reference leak when pm_runtime_get_sync fails (bsc#1220570).
- CVE-2021-47054: Fixed a bug to put child node before return (bsc#1220767).
- CVE-2021-46924: Fixed fix memory leak in device probe and remove (bsc#1220459)
- CVE-2021-46915: Fixed a bug to avoid possible divide error in nft_limit_init (bsc#1220436).
- CVE-2021-46906: Fixed an info leak in hid_submit_ctrl (bsc#1220421).
- CVE-2023-52445: Fixed use after free on context disconnection (bsc#1220241).
- CVE-2020-36777: Fixed a memory leak in dvb_media_device_free (bsc#1220526).
- CVE-2023-52443: Fixed crash ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.201.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.201.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.201.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.201.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.201.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.201.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.201.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.201.1", rls:"SLES12.0SP5"))) {
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
