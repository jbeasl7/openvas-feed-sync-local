# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.3386.1");
  script_cve_id("CVE-2020-3702", "CVE-2021-3744", "CVE-2021-3752", "CVE-2021-3764", "CVE-2021-40490");
  script_tag(name:"creation_date", value:"2021-10-13 06:29:00 +0000 (Wed, 13 Oct 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-28 19:47:28 +0000 (Mon, 28 Feb 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:3386-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:3386-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20213386-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050244");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056653");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056657");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056787");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104745");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109837");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111981");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114648");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118661");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129770");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1148868");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158533");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173746");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176940");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181193");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184439");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185677");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185727");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186785");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189297");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189407");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189884");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190023");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190115");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190159");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190523");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190534");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190543");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190576");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190601");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190620");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190626");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190717");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190914");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191136");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191193");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-October/009580.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:3386-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP56 kernel was updated.


The following security bugs were fixed:

- CVE-2020-3702: Fixed a bug which could be triggered with specifically timed and handcrafted traffic and cause internal errors in a WLAN device that lead to improper layer 2 Wi-Fi encryption with a consequent possibility of information disclosure. (bnc#1191193)
- CVE-2021-3752: Fixed a use after free vulnerability in the Linux kernel's bluetooth module. (bsc#1190023)
- CVE-2021-40490: Fixed a race condition discovered in the ext4 subsystem that could lead to local privilege escalation. (bnc#1190159)
- CVE-2021-3744: Fixed a bug which could allows attackers to cause a denial of service. (bsc#1189884)
- CVE-2021-3764: Fixed a bug which could allows attackers to cause a denial of service. (bsc#1190534)

The following non-security bugs were fixed:

- be2net: Fix an error handling path in 'be_probe()' (git-fixes).
- bnx2x: fix an error code in bnx2x_nic_load() (git-fixes).
- bnxt: Add missing DMA memory barriers (git-fixes).
- bnxt: do not disable an already disabled PCI device (git-fixes).
- bnxt: disable napi before canceling DIM (bsc#1104745 ).
- btrfs: prevent rename2 from exchanging a subvol with a directory from different parents (bsc#1190626).
- clk: at91: clk-generated: Limit the requested rate to our range (git-fixes).
- clk: kirkwood: Fix a clocking boot regression (git-fixes).
- crypto: x86/aes-ni-xts - use direct calls to and 4-way stride (bsc#1114648).
- cxgb4: fix IRQ free race during driver unload (git-fixes).
- debugfs: Return error during {full/open}_proxy_open() on rmmod (bsc#1173746).
- docs: Fix infiniband uverbs minor number (git-fixes).
- drm/gma500: Fix end of loop tests for list_for_each_entry (bsc#1129770) Backporting changes: * refresh
- drm/imx: ipuv3-plane: Remove two unnecessary export symbols (bsc#1129770) Backporting changes: * refreshed
- drm/mediatek: Add AAL output size configuration (bsc#1129770) Backporting changes: * adapted code to use writel() function
- drm/msm: Small msm_gem_purge() fix (bsc#1129770) Backporting changes: * context changes in msm_gem_purge() * remove test for non-existent msm_gem_is_locked()
- drm/msm/dsi: Fix some reference counted resource leaks (bsc#1129770)
- drm/qxl: lost qxl_bo_kunmap_atomic_page in qxl_image_init_helper() (bsc#1186785).
- drm/rockchip: cdn-dp: fix sign extension on an int multiply for a u64 (bsc#1129770) Backporting changes * context changes
- dt-bindings: pwm: stm32: Add #pwm-cells (git-fixes).
- e1000e: Do not take care about recovery NVM checksum (bsc#1158533).
- e1000e: Fix an error handling path in 'e1000_probe()' (git-fixes).
- e1000e: Fix the max snoop/no-snoop latency for 10M (git-fixes).
- EDAC/i10nm: Fix NVDIMM detection (bsc#1114648).
- fbmem: add margin check to fb_check_caps() (bsc#1129770) Backporting changes: * context chacnges in fb_set_var()
- fm10k: Fix an error handling ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.91.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.91.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.91.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.91.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.91.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.91.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.91.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.91.2", rls:"SLES12.0SP5"))) {
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
