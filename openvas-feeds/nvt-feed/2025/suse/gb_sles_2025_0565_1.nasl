# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.0565.1");
  script_cve_id("CVE-2021-47222", "CVE-2021-47223", "CVE-2024-26644", "CVE-2024-47809", "CVE-2024-48881", "CVE-2024-49948", "CVE-2024-50142", "CVE-2024-52332", "CVE-2024-53155", "CVE-2024-53185", "CVE-2024-53197", "CVE-2024-53227", "CVE-2024-55916", "CVE-2024-56369", "CVE-2024-56532", "CVE-2024-56533", "CVE-2024-56539", "CVE-2024-56574", "CVE-2024-56593", "CVE-2024-56594", "CVE-2024-56600", "CVE-2024-56601", "CVE-2024-56615", "CVE-2024-56623", "CVE-2024-56630", "CVE-2024-56637", "CVE-2024-56641", "CVE-2024-56643", "CVE-2024-56650", "CVE-2024-56661", "CVE-2024-56662", "CVE-2024-56681", "CVE-2024-56700", "CVE-2024-56722", "CVE-2024-56739", "CVE-2024-56747", "CVE-2024-56748", "CVE-2024-56759", "CVE-2024-56763", "CVE-2024-56769", "CVE-2024-57884", "CVE-2024-57890", "CVE-2024-57896", "CVE-2024-57899", "CVE-2024-57903", "CVE-2024-57922", "CVE-2024-57929", "CVE-2024-57931", "CVE-2024-57932", "CVE-2024-57938", "CVE-2025-21653", "CVE-2025-21664", "CVE-2025-21678", "CVE-2025-21682");
  script_tag(name:"creation_date", value:"2025-02-18 12:25:07 +0000 (Tue, 18 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-21 17:45:10 +0000 (Tue, 21 Jan 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:0565-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0565-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250565-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221282");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222072");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222803");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224856");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224857");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232161");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233028");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234855");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234901");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234931");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234934");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234963");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235011");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235040");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235053");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235059");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235132");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235155");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235217");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235230");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235252");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235413");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235426");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235430");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235433");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235464");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235466");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235479");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235500");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235523");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235526");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235533");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235557");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235570");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235627");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235638");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235700");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235714");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235727");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235747");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235750");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235919");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235924");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235948");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235965");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235967");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236080");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236096");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236161");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236182");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236190");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236192");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236262");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236698");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236703");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-February/020360.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2025:0565-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2021-47222: net: bridge: fix vlan tunnel dst refcnt when egressing (bsc#1224857).
- CVE-2021-47223: net: bridge: fix vlan tunnel dst null pointer dereference (bsc#1224856).
- CVE-2024-26644: btrfs: do not abort filesystem when attempting to snapshot deleted subvolume (bsc#1222072).
- CVE-2024-47809: dlm: fix possible lkb_resource null dereference (bsc#1235714).
- CVE-2024-48881: bcache: revert replacing IS_ERR_OR_NULL with IS_ERR again (bsc#1235727).
- CVE-2024-49948: net: add more sanity checks to qdisc_pkt_len_init() (bsc#1232161).
- CVE-2024-50142: xfrm: validate new SA's prefixlen using SA family when sel.family is unset (bsc#1233028).
- CVE-2024-52332: igb: Fix potential invalid memory access in igb_init_module() (bsc#1235700).
- CVE-2024-53155: ocfs2: fix uninitialized value in ocfs2_file_read_iter() (bsc#1234855).
- CVE-2024-53185: smb: client: fix NULL ptr deref in crypto_aead_setkey() (bsc#1234901).
- CVE-2024-53197: ALSA: usb-audio: Fix potential out-of-bound accesses for Extigy and Mbox devices (bsc#1235464).
- CVE-2024-53227: scsi: bfa: Fix use-after-free in bfad_im_module_exit() (bsc#1235011).
- CVE-2024-55916: Drivers: hv: util: Avoid accessing a ringbuffer not initialized yet (bsc#1235747).
- CVE-2024-56369: drm/modes: Avoid divide by zero harder in drm_mode_vrefresh() (bsc#1235750).
- CVE-2024-56532: ALSA: us122l: Use snd_card_free_when_closed() at disconnection (bsc#1235059).
- CVE-2024-56533: ALSA: usx2y: Use snd_card_free_when_closed() at disconnection (bsc#1235053).
- CVE-2024-56539: wifi: mwifiex: Fix memcpy() field-spanning write warning in mwifiex_config_scan() (bsc#1234963).
- CVE-2024-56574: media: ts2020: fix null-ptr-deref in ts2020_probe() (bsc#1235040).
- CVE-2024-56593: wifi: brcmfmac: Fix oops due to NULL pointer dereference in brcmf_sdiod_sglist_rw() (bsc#1235252).
- CVE-2024-56594: drm/amdgpu: set the right AMDGPU sg segment limitation (bsc#1235413).
- CVE-2024-56600: net: inet6: do not leave a dangling sk pointer in inet6_create() (bsc#1235217).
- CVE-2024-56601: net: inet: do not leave a dangling sk pointer in inet_create() (bsc#1235230).
- CVE-2024-56615: bpf: fix OOB devmap writes when deleting elements (bsc#1235426).
- CVE-2024-56623: scsi: qla2xxx: Fix use after free on unload (bsc#1235466).
- CVE-2024-56630: ocfs2: free inode when ocfs2_get_init_inode() fails (bsc#1235479).
- CVE-2024-56637: netfilter: ipset: Hold module reference while requesting a module (bsc#1235523).
- CVE-2024-56641: net/smc: initialize close_work early to avoid warning (bsc#1235526).
- CVE-2024-56643: dccp: Fix memory leak in dccp_feat_change_recv (bsc#1235132).
- CVE-2024-56650: netfilter: x_tables: fix LED ID check in led_tg_check() (bsc#1235430).
- CVE-2024-56662: acpi: nfit: vmalloc-out-of-bounds Read in acpi_nfit_ctl ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-default", rpm:"cluster-md-kmp-default~4.12.14~122.247.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-default", rpm:"dlm-kmp-default~4.12.14~122.247.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-default", rpm:"gfs2-kmp-default~4.12.14~122.247.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.247.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.247.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.247.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.247.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.247.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.247.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.247.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.247.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-default", rpm:"ocfs2-kmp-default~4.12.14~122.247.1", rls:"SLES12.0SP5"))) {
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
