# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.4616.1");
  script_cve_id("CVE-2022-2602", "CVE-2022-28693", "CVE-2022-29900", "CVE-2022-29901", "CVE-2022-3567", "CVE-2022-3628", "CVE-2022-3635", "CVE-2022-3707", "CVE-2022-3903", "CVE-2022-4095", "CVE-2022-4129", "CVE-2022-4139", "CVE-2022-41850", "CVE-2022-41858", "CVE-2022-42895", "CVE-2022-42896", "CVE-2022-4378", "CVE-2022-43945", "CVE-2022-45934");
  script_tag(name:"creation_date", value:"2022-12-26 04:19:22 +0000 (Mon, 26 Dec 2022)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-28 01:27:19 +0000 (Mon, 28 Nov 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:4616-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:4616-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20224616-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1071995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1156395");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184350");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189297");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192761");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199657");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1200845");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201455");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201469");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203144");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203746");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203960");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204017");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204142");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204215");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204228");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204241");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204328");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204414");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204446");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204636");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204693");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204780");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204791");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204810");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204827");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204850");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204868");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204934");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204957");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204963");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204967");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205128");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205130");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205220");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205264");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205329");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205330");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205473");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205567");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205617");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205671");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205700");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205705");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205709");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205753");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205796");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205984");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205985");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205986");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205987");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205988");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205989");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206037");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206207");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-December/013339.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:4616-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

- CVE-2022-4378: Fixed stack overflow in __do_proc_dointvec (bsc#1206207).
- CVE-2022-3635: Fixed a use-after-free in the tst_timer() of the file drivers/atm/idt77252.c (bsc#1204631).
- CVE-2022-41850: Fixed a race condition in roccat_report_event() in drivers/hid/hid-roccat.c (bsc#1203960).
- CVE-2022-45934: Fixed a integer wraparound via L2CAP_CONF_REQ packets in l2cap_config_req in net/bluetooth/l2cap_core.c (bsc#1205796).
- CVE-2022-3628: Fixed potential buffer overflow in brcmf_fweh_event_worker() in wifi/brcmfmac (bsc#1204868).
- CVE-2022-3567: Fixed a to race condition in inet6_stream_ops()/inet6_dgram_ops() (bsc#1204414).
- CVE-2022-41858: Fixed a denial of service in sl_tx_timeout() in drivers/net/slip (bsc#1205671).
- CVE-2022-43945: Fixed a buffer overflow in the NFSD implementation (bsc#1205128).
- CVE-2022-4095: Fixed a use-after-free in rtl8712 driver (bsc#1205514).
- CVE-2022-3903: Fixed a denial of service with the Infrared Transceiver USB driver (bsc#1205220).
- CVE-2022-2602: Fixed a local privilege escalation vulnerability involving Unix socket Garbage Collection and io_uring (bsc#1204228).
- CVE-2022-4139: Fixed an issue with the i915 driver that allowed the GPU to access any physical memory (bsc#1205700).
- CVE-2022-4129: Fixed a denial of service with the Layer 2 Tunneling Protocol (L2TP). A missing lock when clearing sk_user_data can lead to a race condition and NULL pointer dereference. (bsc#1205711)
- CVE-2022-42895: Fixed an information leak in the net/bluetooth/l2cap_core.c's l2cap_parse_conf_req() which can be used to leak kernel pointers remotely (bsc#1205705).
- CVE-2022-42896: Fixed a use-after-free vulnerability in the net/bluetooth/l2cap_core.c's l2cap_connect() and l2cap_le_connect_req() which may have allowed code execution and leaking kernel memory (respectively) remotely via Bluetooth (bsc#1205709).
- CVE-2022-3707: Fixed a double free in the Intel GVT-g graphics driver (bsc#1204780).

The following non-security bugs were fixed:

- ALSA: hda/ca0132: add quirk for EVGA Z390 DARK (git-fixes).
- ALSA: hda: fix potential memleak in 'add_widget_node' (git-fixes).
- ALSA: usb-audio: Add DSD support for Accuphase DAC-60 (git-fixes).
- ALSA: usb-audio: Add quirk entry for M-Audio Micro (git-fixes).
- ALSA: usb-audio: Drop snd_BUG_ON() from snd_usbmidi_output_open() (git-fixes).
- ASoC: codecs: jz4725b: Fix spelling mistake 'Sourc' -> 'Source', 'Routee' -> 'Route' (git-fixes).
- ASoC: codecs: jz4725b: add missed Line In power control bit (git-fixes).
- ASoC: codecs: jz4725b: fix capture selector naming (git-fixes).
- ASoC: codecs: jz4725b: fix reported volume for Master ctl (git-fixes).
- ASoC: codecs: jz4725b: use right control for Capture Volume (git-fixes).
- ASoC: core: Fix use-after-free in ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.3.18~150300.59.106.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-debuginfo", rpm:"kernel-64kb-debuginfo~5.3.18~150300.59.106.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-debugsource", rpm:"kernel-64kb-debugsource~5.3.18~150300.59.106.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.3.18~150300.59.106.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel-debuginfo", rpm:"kernel-64kb-devel-debuginfo~5.3.18~150300.59.106.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~150300.59.106.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~150300.59.106.1.150300.18.60.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~5.3.18~150300.59.106.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~5.3.18~150300.59.106.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~150300.59.106.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~5.3.18~150300.59.106.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~150300.59.106.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~150300.59.106.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~150300.59.106.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-debuginfo", rpm:"kernel-preempt-debuginfo~5.3.18~150300.59.106.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-debugsource", rpm:"kernel-preempt-debugsource~5.3.18~150300.59.106.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.3.18~150300.59.106.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debuginfo", rpm:"kernel-zfcpdump-debuginfo~5.3.18~150300.59.106.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debugsource", rpm:"kernel-zfcpdump-debugsource~5.3.18~150300.59.106.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~150300.59.106.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~150300.59.106.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~5.3.18~150300.59.106.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~150300.59.106.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel-debuginfo", rpm:"kernel-preempt-devel-debuginfo~5.3.18~150300.59.106.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~150300.59.106.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~150300.59.106.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.3.18~150300.59.106.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default-debuginfo", rpm:"reiserfs-kmp-default-debuginfo~5.3.18~150300.59.106.1", rls:"SLES15.0SP3"))) {
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
