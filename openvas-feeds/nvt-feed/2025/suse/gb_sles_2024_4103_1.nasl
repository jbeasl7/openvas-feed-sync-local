# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.4103.1");
  script_cve_id("CVE-2021-47416", "CVE-2021-47589", "CVE-2022-3435", "CVE-2022-45934", "CVE-2022-48664", "CVE-2022-48947", "CVE-2022-48956", "CVE-2022-48960", "CVE-2022-48962", "CVE-2022-48967", "CVE-2022-48970", "CVE-2022-48988", "CVE-2022-48991", "CVE-2022-48999", "CVE-2022-49003", "CVE-2022-49014", "CVE-2022-49015", "CVE-2022-49023", "CVE-2022-49025", "CVE-2023-28327", "CVE-2023-46343", "CVE-2023-52881", "CVE-2023-52919", "CVE-2023-6270", "CVE-2024-27043", "CVE-2024-42145", "CVE-2024-44947", "CVE-2024-45016", "CVE-2024-46813", "CVE-2024-46816", "CVE-2024-46817", "CVE-2024-46818", "CVE-2024-46849", "CVE-2024-47668", "CVE-2024-47674", "CVE-2024-47684", "CVE-2024-47706", "CVE-2024-47747", "CVE-2024-49860", "CVE-2024-49867", "CVE-2024-49936", "CVE-2024-49974", "CVE-2024-49982", "CVE-2024-49991", "CVE-2024-49995", "CVE-2024-50047");
  script_tag(name:"creation_date", value:"2025-02-13 14:53:48 +0000 (Thu, 13 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-23 22:16:21 +0000 (Wed, 23 Oct 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:4103-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:4103-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20244103-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195775");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204171");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205796");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206344");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209290");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219125");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223384");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223524");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223824");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225336");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226211");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226212");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226557");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228743");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229042");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229454");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229456");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230429");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231073");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231191");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231197");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231200");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231203");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231293");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231375");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231502");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231673");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231861");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231887");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231890");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231893");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231895");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231936");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231938");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231942");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231960");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231961");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231979");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231987");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231988");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232033");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232069");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232070");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232097");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232136");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232145");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232262");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232282");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232286");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232304");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232383");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232418");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232424");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232432");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-November/019863.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2024:4103-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP2 LTSS kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2021-47589: igbvf: fix double free in `igbvf_probe` (bsc#1226557).
- CVE-2022-48956: ipv6: avoid use-after-free in ip6_fragment() (bsc#1231893).
- CVE-2022-48960: net: hisilicon: Fix potential use-after-free in hix5hd2_rx() (bsc#1231979).
- CVE-2022-48962: net: hisilicon: Fix potential use-after-free in hisi_femac_rx() (bsc#1232286).
- CVE-2022-48967: NFC: nci: Bounds check struct nfc_target arrays (bsc#1232304).
- CVE-2022-48988: memcg: Fix possible use-after-free in memcg_write_event_control() (bsc#1206344 bsc#1232069).
- CVE-2022-48991: khugepaged: retract_page_tables() remember to test exit (bsc#1232070).
- CVE-2022-49003: nvme: fix SRCU protection of nvme_ns_head list (bsc#1232136).
- CVE-2022-49014: net: tun: Fix use-after-free in tun_detach() (bsc#1231890).
- CVE-2022-49015: net: hsr: Fix potential use-after-free (bsc#1231938).
- CVE-2022-49023: wifi: cfg80211: fix buffer overflow in elem comparison (bsc#1231961).
- CVE-2022-49025: net/mlx5e: Fix use-after-free when reverting termination table (bsc#1231960).
- CVE-2024-45016: netem: fix return value if duplicate enqueue fails (bsc#1230429).
- CVE-2024-46813: drm/amd/display: Check link_index before accessing dc->links (bsc#1231191).
- CVE-2024-46816: drm/amd/display: Stop amdgpu_dm initialize when link nums greater than max_links (bsc#1231197).
- CVE-2024-46817: drm/amd/display: Stop amdgpu_dm initialize when stream nums greater than 6 (bsc#1231200).
- CVE-2024-46818: drm/amd/display: Check gpio_id before used as array index (bsc#1231203).
- CVE-2024-46849: ASoC: meson: axg-card: fix 'use-after-free' (bsc#1231073).
- CVE-2024-47668: lib/generic-radix-tree.c: Fix rare race in __genradix_ptr_alloc() (bsc#1231502).
- CVE-2024-47674: mm: avoid leaving partial pfn mappings around in error case (bsc#1231673).
- CVE-2024-47684: tcp: check skb is non-NULL in tcp_rto_delta_us() (bsc#1231987).
- CVE-2024-47706: block, bfq: fix possible UAF for bfqq->bic with merge chain (bsc#1231942).
- CVE-2024-47747: net: seeq: Fix use after free vulnerability in ether3 Driver Due to Race Condition (bsc#1232145).
- CVE-2024-49860: ACPI: sysfs: validate return type of _STR method (bsc#1231861).
- CVE-2024-49936: net/xen-netback: prevent UAF in xenvif_flush_hash() (bsc#1232424).
- CVE-2024-49974: NFSD: Force all NFSv4.2 COPY requests to be synchronous (bsc#1232383).
- CVE-2024-49991: drm/amdkfd: amdkfd_free_gtt_mem clear the correct pointer (bsc#1232282).
- CVE-2024-49995: tipc: guard against string buffer overrun (bsc#1232432).
- CVE-2024-50047: smb: client: fix UAF in async decryption (bsc#1232418).

The following non-security bugs were fixed:

- initrd: Revert 'build initrd without systemd' (bsc#1195775).
- bpf: Fix pointer-leak due to insufficient speculative store bypass mitigation ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP2.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~150200.24.209.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~150200.24.209.1.150200.9.109.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~150200.24.209.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~150200.24.209.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~150200.24.209.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~150200.24.209.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~150200.24.209.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~150200.24.209.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~150200.24.209.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~150200.24.209.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~150200.24.209.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.3.18~150200.24.209.1", rls:"SLES15.0SP2"))) {
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
