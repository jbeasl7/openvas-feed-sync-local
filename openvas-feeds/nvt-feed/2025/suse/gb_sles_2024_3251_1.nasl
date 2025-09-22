# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.3251.1");
  script_cve_id("CVE-2021-4440", "CVE-2021-47257", "CVE-2021-47289", "CVE-2021-47341", "CVE-2021-47373", "CVE-2021-47425", "CVE-2021-47549", "CVE-2022-48751", "CVE-2022-48769", "CVE-2022-48786", "CVE-2022-48822", "CVE-2022-48865", "CVE-2022-48875", "CVE-2022-48896", "CVE-2022-48899", "CVE-2022-48905", "CVE-2022-48910", "CVE-2022-48919", "CVE-2022-48920", "CVE-2022-48925", "CVE-2022-48930", "CVE-2022-48931", "CVE-2022-48938", "CVE-2023-2176", "CVE-2023-52708", "CVE-2023-52893", "CVE-2023-52901", "CVE-2023-52907", "CVE-2024-26668", "CVE-2024-26677", "CVE-2024-26812", "CVE-2024-26851", "CVE-2024-27011", "CVE-2024-35915", "CVE-2024-35933", "CVE-2024-35965", "CVE-2024-36013", "CVE-2024-36270", "CVE-2024-36286", "CVE-2024-38618", "CVE-2024-38662", "CVE-2024-39489", "CVE-2024-40984", "CVE-2024-41012", "CVE-2024-41016", "CVE-2024-41020", "CVE-2024-41035", "CVE-2024-41062", "CVE-2024-41068", "CVE-2024-41087", "CVE-2024-41097", "CVE-2024-41098", "CVE-2024-42077", "CVE-2024-42082", "CVE-2024-42090", "CVE-2024-42101", "CVE-2024-42106", "CVE-2024-42110", "CVE-2024-42148", "CVE-2024-42155", "CVE-2024-42157", "CVE-2024-42158", "CVE-2024-42162", "CVE-2024-42226", "CVE-2024-42228", "CVE-2024-42232", "CVE-2024-42236", "CVE-2024-42240", "CVE-2024-42244", "CVE-2024-42246", "CVE-2024-42259", "CVE-2024-42271", "CVE-2024-42280", "CVE-2024-42281", "CVE-2024-42284", "CVE-2024-42285", "CVE-2024-42286", "CVE-2024-42287", "CVE-2024-42288", "CVE-2024-42289", "CVE-2024-42301", "CVE-2024-42309", "CVE-2024-42310", "CVE-2024-42312", "CVE-2024-42322", "CVE-2024-43819", "CVE-2024-43831", "CVE-2024-43839", "CVE-2024-43853", "CVE-2024-43854", "CVE-2024-43856", "CVE-2024-43861", "CVE-2024-43863", "CVE-2024-43866", "CVE-2024-43871", "CVE-2024-43872", "CVE-2024-43879", "CVE-2024-43882", "CVE-2024-43883", "CVE-2024-43892", "CVE-2024-43893", "CVE-2024-43900", "CVE-2024-43902", "CVE-2024-43905", "CVE-2024-43907");
  script_tag(name:"creation_date", value:"2025-02-13 14:53:48 +0000 (Thu, 13 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-27 14:38:32 +0000 (Tue, 27 Aug 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:3251-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3251-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243251-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082555");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190317");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196516");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205462");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210629");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214285");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216834");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221252");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222335");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222387");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222808");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223074");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223803");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224479");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224579");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224640");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224896");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224923");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224984");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225190");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225223");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225483");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225508");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225578");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226323");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226629");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226653");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226754");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226798");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226801");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226885");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227069");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227623");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227820");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227996");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228065");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228247");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228410");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228427");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228449");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228466");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228467");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228482");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228485");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228487");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228493");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228495");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228501");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228513");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228516");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228576");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228579");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228667");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228706");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228709");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228720");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228727");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228733");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228801");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228850");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228959");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228964");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228966");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228967");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228982");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228989");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229154");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229156");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229222");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229229");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229290");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229292");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229301");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229309");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229327");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229345");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229346");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229347");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229357");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229358");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229359");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229381");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229386");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229388");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229392");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229395");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229398");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229399");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229407");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229457");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229462");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229482");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229489");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229490");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229495");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229497");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229500");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229503");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229516");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229526");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229531");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229535");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229536");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229540");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229604");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229623");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229624");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229630");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229632");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229657");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229658");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229664");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229707");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229756");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229759");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229761");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229767");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229784");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229787");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229851");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-September/036895.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2024:3251-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security bugfixes.

The following security bugs were fixed:

- CVE-2024-35965: Fix not validating setsockopt user input (bsc#1224579).
- CVE-2024-35933: Fixed build regression (bsc#1224640).
- CVE-2024-43883: Do not drop references before new references are gained (bsc#1229707).
- CVE-2024-41062: Sync sock recv cb and release (bsc#1228576).
- CVE-2024-42259: Fix Virtual Memory mapping boundaries calculation (bsc#1229156)
- CVE-2024-43861: Fix memory leak for not ip packets (bsc#1229500).
- CVE-2024-43863: Fix a deadlock in dma buf fence polling (bsc#1229497)
- CVE-2024-41087: Fix double free on error (bsc#1228466).
- CVE-2024-43907: Fix the null pointer dereference in apply_state_adjust_rules (bsc#1229787).
- CVE-2024-43905: Fix the null pointer dereference for vega10_hwmgr (bsc#1229784).
- CVE-2024-43893: Check uartclk for zero to avoid divide by zero (bsc#1229759).
- CVE-2024-43900: Avoid use-after-free in load_firmware_cb() (bsc#1229756).
- CVE-2024-43902: Add null checker before passing variables (bsc#1229767).
- CVE-2022-48920: Get rid of warning on transaction commit when using flushoncommit (bsc#1229658).
- CVE-2024-26812: Struct virqfd kABI workaround (bsc#1222808).
- CVE-2024-43882: Fixed ToCToU between perm check and set-uid/gid usage. (bsc#1229503)
- CVE-2024-43866: Always drain health in shutdown callback (bsc#1229495).
- CVE-2022-48910: Ensure we call ipv6_mc_down() at most once (bsc#1229632)
- CVE-2023-52893: Fix null-deref in gsmi_get_variable (bsc#1229535)
- CVE-2024-42155: Wipe copies of protected- and secure-keys (bsc#1228733).
- CVE-2022-48875: Initialize struct pn533_out_arg properly (bsc#1229516).
- CVE-2023-52907: Wait for out_urb's completion in pn533_usb_send_frame() (bsc#1229526).
- CVE-2024-43871: Fix memory leakage caused by driver API devm_free_percpu() (bsc#1229490)
- CVE-2024-42158: Use kfree_sensitive() to fix Coccinelle warnings (bsc#1228720).
- CVE-2024-43872: Fix soft lockup under heavy CEQE load (bsc#1229489)
- CVE-2024-39489: Fix memleak in seg6_hmac_init_algo (bsc#1227623)
- CVE-2024-42226: Prevent potential failure in handle_tx_event() for Transfer events without TRB (bsc#1228709).
- CVE-2024-42236: Prevent OOB read/write in usb_string_copy() (bsc#1228964).
- CVE-2024-42244: Fix crash on resume (bsc#1228967).
- CVE-2024-43879: Handle 2x996 RU allocation in cfg80211_calculate_bitrate_he() (bsc#1229482).
- CVE-2024-27011: Fix memleak in map from abort path (bsc#1223803).
- CVE-2024-36013: Fix slab-use-after-free in l2cap_connect() (bsc#1225578).
- CVE-2024-41020: Fix fcntl/close race recovery compat path (bsc#1228427).
- CVE-2024-41012: Remove locks reliably when fcntl/close race is detected (bsc#1228247).
- CVE-2024-26668: Reject configurations that cause integer overflow (bsc#1222335).
- CVE-2024-43819: Reject memory region operations for ucontrol VMs ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.228.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.228.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.228.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.228.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.228.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.228.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.228.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.228.1", rls:"SLES12.0SP5"))) {
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
