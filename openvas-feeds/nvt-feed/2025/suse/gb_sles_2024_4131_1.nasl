# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.4131.1");
  script_cve_id("CVE-2021-47416", "CVE-2021-47534", "CVE-2022-3435", "CVE-2022-45934", "CVE-2022-48664", "CVE-2022-48879", "CVE-2022-48946", "CVE-2022-48947", "CVE-2022-48948", "CVE-2022-48949", "CVE-2022-48951", "CVE-2022-48953", "CVE-2022-48954", "CVE-2022-48955", "CVE-2022-48956", "CVE-2022-48959", "CVE-2022-48960", "CVE-2022-48961", "CVE-2022-48962", "CVE-2022-48967", "CVE-2022-48968", "CVE-2022-48969", "CVE-2022-48970", "CVE-2022-48971", "CVE-2022-48972", "CVE-2022-48973", "CVE-2022-48975", "CVE-2022-48977", "CVE-2022-48978", "CVE-2022-48981", "CVE-2022-48985", "CVE-2022-48987", "CVE-2022-48988", "CVE-2022-48991", "CVE-2022-48992", "CVE-2022-48994", "CVE-2022-48995", "CVE-2022-48997", "CVE-2022-48999", "CVE-2022-49000", "CVE-2022-49002", "CVE-2022-49003", "CVE-2022-49005", "CVE-2022-49006", "CVE-2022-49007", "CVE-2022-49010", "CVE-2022-49011", "CVE-2022-49012", "CVE-2022-49014", "CVE-2022-49015", "CVE-2022-49016", "CVE-2022-49019", "CVE-2022-49021", "CVE-2022-49022", "CVE-2022-49023", "CVE-2022-49024", "CVE-2022-49025", "CVE-2022-49026", "CVE-2022-49027", "CVE-2022-49028", "CVE-2022-49029", "CVE-2022-49031", "CVE-2022-49032", "CVE-2023-2166", "CVE-2023-28327", "CVE-2023-52766", "CVE-2023-52800", "CVE-2023-52881", "CVE-2023-52919", "CVE-2023-6270", "CVE-2024-27043", "CVE-2024-42145", "CVE-2024-43854", "CVE-2024-44947", "CVE-2024-45013", "CVE-2024-45016", "CVE-2024-45026", "CVE-2024-46716", "CVE-2024-46813", "CVE-2024-46814", "CVE-2024-46815", "CVE-2024-46816", "CVE-2024-46817", "CVE-2024-46818", "CVE-2024-46849", "CVE-2024-47668", "CVE-2024-47674", "CVE-2024-47684", "CVE-2024-47706", "CVE-2024-47747", "CVE-2024-47748", "CVE-2024-49860", "CVE-2024-49867", "CVE-2024-49925", "CVE-2024-49930", "CVE-2024-49936", "CVE-2024-49945", "CVE-2024-49960", "CVE-2024-49969", "CVE-2024-49974", "CVE-2024-49982", "CVE-2024-49991", "CVE-2024-49995", "CVE-2024-50047", "CVE-2024-50208");
  script_tag(name:"creation_date", value:"2025-02-13 14:53:48 +0000 (Thu, 13 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-23 22:16:21 +0000 (Wed, 23 Oct 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:4131-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:4131-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20244131-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204171");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205796");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206188");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206344");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209290");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210449");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210627");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213034");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216223");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216813");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223384");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223524");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223824");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225189");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225336");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228743");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229345");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229452");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229454");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229456");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229556");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230429");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230442");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230454");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230620");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230715");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230903");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231016");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231073");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231191");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231193");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231195");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231197");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231200");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231203");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231293");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231375");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231502");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231673");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231861");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231883");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231885");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231887");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231888");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231890");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231892");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231893");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231895");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231896");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231897");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231929");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231936");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231937");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231938");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231939");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231940");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231941");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231942");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231958");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231960");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231961");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231962");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231972");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231976");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231979");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231987");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231988");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231991");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231992");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231996");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231997");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232001");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232005");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232006");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232007");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232025");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232026");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232033");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232035");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232036");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232037");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232039");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232067");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232069");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232070");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232071");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232097");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232108");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232119");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232120");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232123");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232133");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232136");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232145");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232150");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232163");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232165");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232170");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232172");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232174");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232224");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232229");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232237");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232260");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232262");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232281");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232282");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232286");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232304");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232383");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232395");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232418");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232424");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232432");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232436");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232519");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233117");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-December/019887.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2024:4131-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP4 kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2024-43854: Initialize integrity buffer to zero before writing it to media (bsc#1229345)
- CVE-2024-49925: fbdev: efifb: Register sysfs groups through driver core (bsc#1232224)
- CVE-2024-49945: net/ncsi: Disable the ncsi work before freeing the associated structure (bsc#1232165).
- CVE-2024-50208: RDMA/bnxt_re: Fix a bug while setting up Level-2 PBL pages (bsc#1233117).
- CVE-2022-48879: efi: fix NULL-deref in init error path (bsc#1229556).
- CVE-2022-48956: ipv6: avoid use-after-free in ip6_fragment() (bsc#1231893).
- CVE-2022-48959: net: dsa: sja1105: fix memory leak in sja1105_setup_devlink_regions() (bsc#1231976).
- CVE-2022-48960: net: hisilicon: Fix potential use-after-free in hix5hd2_rx() (bsc#1231979).
- CVE-2022-48962: net: hisilicon: Fix potential use-after-free in hisi_femac_rx() (bsc#1232286).
- CVE-2022-48991: mm/khugepaged: fix collapse_pte_mapped_thp() to allow anon_vma (bsc#1232070).
- CVE-2022-49015: net: hsr: Fix potential use-after-free (bsc#1231938).
- CVE-2024-45013: nvme: move stopping keep-alive into nvme_uninit_ctrl() (bsc#1230442).
- CVE-2024-45016: netem: fix return value if duplicate enqueue fails (bsc#1230429).
- CVE-2024-45026: s390/dasd: fix error recovery leading to data corruption on ESE devices (bsc#1230454).
- CVE-2024-46716: dmaengine: altera-msgdma: properly free descriptor in msgdma_free_descriptor (bsc#1230715).
- CVE-2024-46813: drm/amd/display: Check link_index before accessing dc->links (bsc#1231191).
- CVE-2024-46814: drm/amd/display: Check msg_id before processing transcation (bsc#1231193).
- CVE-2024-46815: drm/amd/display: Check num_valid_sets before accessing reader_wm_sets (bsc#1231195).
- CVE-2024-46816: drm/amd/display: Stop amdgpu_dm initialize when link nums greater than max_links (bsc#1231197).
- CVE-2024-46817: drm/amd/display: Stop amdgpu_dm initialize when stream nums greater than 6 (bsc#1231200).
- CVE-2024-46818: drm/amd/display: Check gpio_id before used as array index (bsc#1231203).
- CVE-2024-46849: ASoC: meson: axg-card: fix 'use-after-free' (bsc#1231073).
- CVE-2024-47668: lib/generic-radix-tree.c: Fix rare race in __genradix_ptr_alloc() (bsc#1231502).
- CVE-2024-47674: mm: avoid leaving partial pfn mappings around in error case (bsc#1231673).
- CVE-2024-47684: tcp: check skb is non-NULL in tcp_rto_delta_us() (bsc#1231987).
- CVE-2024-47706: block, bfq: fix possible UAF for bfqq->bic with merge chain (bsc#1231942).
- CVE-2024-47747: net: seeq: Fix use after free vulnerability in ether3 Driver Due to Race Condition (bsc#1232145).
- CVE-2024-47748: vhost_vdpa: assign irq bypass producer token correctly (bsc#1232174).
- CVE-2024-49860: ACPI: sysfs: validate return type of _STR method (bsc#1231861).
- CVE-2024-49930: wifi: ath11k: fix array out-of-bound access in SoC stats ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.14.21~150400.24.141.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.14.21~150400.24.141.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.14.21~150400.24.141.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.14.21~150400.24.141.1.150400.24.68.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.14.21~150400.24.141.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.14.21~150400.24.141.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.14.21~150400.24.141.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.14.21~150400.24.141.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.14.21~150400.24.141.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.14.21~150400.24.141.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.14.21~150400.24.141.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.14.21~150400.24.141.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.14.21~150400.24.141.1", rls:"SLES15.0SP4"))) {
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
