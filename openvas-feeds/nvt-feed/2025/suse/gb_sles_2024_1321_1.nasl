# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.1321.1");
  script_cve_id("CVE-2021-46925", "CVE-2021-46926", "CVE-2021-46927", "CVE-2021-46929", "CVE-2021-46930", "CVE-2021-46931", "CVE-2021-46933", "CVE-2021-46936", "CVE-2021-47082", "CVE-2021-47087", "CVE-2021-47091", "CVE-2021-47093", "CVE-2021-47094", "CVE-2021-47095", "CVE-2021-47096", "CVE-2021-47097", "CVE-2021-47098", "CVE-2021-47099", "CVE-2021-47100", "CVE-2021-47101", "CVE-2021-47102", "CVE-2021-47104", "CVE-2021-47105", "CVE-2021-47107", "CVE-2021-47108", "CVE-2022-20154", "CVE-2022-4744", "CVE-2022-48626", "CVE-2022-48629", "CVE-2022-48630", "CVE-2023-28746", "CVE-2023-35827", "CVE-2023-52447", "CVE-2023-52450", "CVE-2023-52454", "CVE-2023-52469", "CVE-2023-52470", "CVE-2023-52474", "CVE-2023-52477", "CVE-2023-52492", "CVE-2023-52497", "CVE-2023-52501", "CVE-2023-52502", "CVE-2023-52504", "CVE-2023-52507", "CVE-2023-52508", "CVE-2023-52509", "CVE-2023-52510", "CVE-2023-52511", "CVE-2023-52513", "CVE-2023-52515", "CVE-2023-52517", "CVE-2023-52519", "CVE-2023-52520", "CVE-2023-52523", "CVE-2023-52524", "CVE-2023-52525", "CVE-2023-52528", "CVE-2023-52529", "CVE-2023-52532", "CVE-2023-52564", "CVE-2023-52566", "CVE-2023-52567", "CVE-2023-52569", "CVE-2023-52574", "CVE-2023-52575", "CVE-2023-52576", "CVE-2023-52582", "CVE-2023-52583", "CVE-2023-52597", "CVE-2023-52605", "CVE-2023-52621", "CVE-2023-6356", "CVE-2023-6535", "CVE-2023-6536", "CVE-2024-25742", "CVE-2024-26600");
  script_tag(name:"creation_date", value:"2025-02-13 14:53:48 +0000 (Thu, 13 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-17 15:20:01 +0000 (Mon, 17 Mar 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:1321-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1321-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20241321-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1200599");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213456");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217987");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217988");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217989");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220237");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220251");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220320");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220340");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220366");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220411");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220413");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220439");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220443");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220445");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220466");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220478");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220482");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220484");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220486");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220487");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220790");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220831");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220833");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220836");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220839");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220840");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220843");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220870");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220871");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220872");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220879");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220885");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220898");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220918");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220920");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220921");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220926");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220927");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220929");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220932");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220938");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220940");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220954");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220955");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220959");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220960");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220961");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220965");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220969");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220978");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220979");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220981");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220982");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220983");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220985");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220986");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220987");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220989");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220990");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221009");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221012");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221015");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221022");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221039");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221040");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221048");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221055");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221058");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221077");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221276");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221551");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221553");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221725");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222073");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222619");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-April/035005.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2024:1321-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP4 kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2024-25742: Fixed insufficient validation during #VC instruction emulation in x86/sev (bsc#1221725).
- CVE-2023-52519: Fixed possible overflow in HID/intel-ish-hid/ipc (bsc#1220920).
- CVE-2023-52529: Fixed a potential memory leak in sony_probe() (bsc#1220929).
- CVE-2023-52474: Fixed a vulnerability with non-PAGE_SIZE-end multi-iovec user SDMA requests (bsc#1220445).
- CVE-2023-52513: Fixed connection failure handling in RDMA/siw (bsc#1221022).
- CVE-2023-52515: Fixed possible use-after-free in RDMA/srp (bsc#1221048).
- CVE-2023-52564: Reverted invalid fix for UAF in gsm_cleanup_mux() (bsc#1220938).
- CVE-2023-52447: Fixed map_fd_put_ptr() signature kABI workaround (bsc#1220251).
- CVE-2023-52510: Fixed a potential UAF in ca8210_probe() (bsc#1220898).
- CVE-2023-52524: Fixed possible corruption in nfc/llcp (bsc#1220927).
- CVE-2023-52528: Fixed uninit-value access in __smsc75xx_read_reg() (bsc#1220843).
- CVE-2023-52507: Fixed possible shift-out-of-bounds in nfc/nci (bsc#1220833).
- CVE-2023-52566: Fixed potential use after free in nilfs_gccache_submit_read_data() (bsc#1220940).
- CVE-2023-52508: Fixed null pointer dereference in nvme_fc_io_getuuid() (bsc#1221015).
- CVE-2023-6535: Fixed a NULL pointer dereference in nvmet_tcp_execute_request (bsc#1217988).
- CVE-2023-6536: Fixed a NULL pointer dereference in __nvmet_req_complete (bsc#1217989).
- CVE-2023-6356: Fixed a NULL pointer dereference in nvmet_tcp_build_pdu_iovec (bsc#1217987).
- CVE-2023-52454: Fixed a kernel panic when host sends an invalid H2C PDU length (bsc#1220320).
- CVE-2023-52520: Fixed reference leak in platform/x86/think-lmi (bsc#1220921).
- CVE-2023-35827: Fixed a use-after-free issue in ravb_tx_timeout_work() (bsc#1212514).
- CVE-2023-52509: Fixed a use-after-free issue in ravb_tx_timeout_work() (bsc#1220836).
- CVE-2023-52501: Fixed possible memory corruption in ring-buffer (bsc#1220885).
- CVE-2023-52567: Fixed possible Oops in serial/8250_port: when using IRQ polling (irq = 0) (bsc#1220839).
- CVE-2023-52517: Fixed race between DMA RX transfer completion and RX FIFO drain in spi/sun6i (bsc#1221055).
- CVE-2023-52511: Fixed possible memory corruption in spi/sun6i (bsc#1221012).
- CVE-2023-52525: Fixed out of bounds check mwifiex_process_rx_packet() (bsc#1220840).
- CVE-2023-52504: Fixed possible out-of bounds in apply_alternatives() on a 5-level paging machine (bsc#1221553).
- CVE-2023-52575: Fixed SBPB enablement for spec_rstack_overflow=off (bsc#1220871).
- CVE-2022-48626: Fixed a potential use-after-free on remove path moxart (bsc#1220366).
- CVE-2022-48629: Fixed possible memory leak in qcom-rng (bsc#1220989).
- CVE-2022-48630: Fixed infinite loop on requests not multiple of WORD_SZ in crypto: qcom-rng (bsc#1220990).
- CVE-2021-46926: Fixed bug when ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.14.21~150400.24.116.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.14.21~150400.24.116.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.14.21~150400.24.116.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.14.21~150400.24.116.1.150400.24.54.5", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.14.21~150400.24.116.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.14.21~150400.24.116.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.14.21~150400.24.116.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.14.21~150400.24.116.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.14.21~150400.24.116.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.14.21~150400.24.116.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.14.21~150400.24.116.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.14.21~150400.24.116.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.14.21~150400.24.116.1", rls:"SLES15.0SP4"))) {
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
