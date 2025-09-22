# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.0778.1");
  script_cve_id("CVE-2022-36280", "CVE-2022-38096", "CVE-2023-0045", "CVE-2023-0590", "CVE-2023-0597", "CVE-2023-1118", "CVE-2023-22995", "CVE-2023-23000", "CVE-2023-23006", "CVE-2023-23559", "CVE-2023-26545");
  script_tag(name:"creation_date", value:"2025-02-17 04:07:12 +0000 (Mon, 17 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-23 19:29:19 +0000 (Mon, 23 Jan 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:0778-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0778-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20230778-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186449");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203331");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203332");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204356");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204662");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207773");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207795");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207845");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207875");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208023");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208153");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208212");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208700");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208741");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208813");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208816");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208837");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208845");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208971");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2023-March/014073.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2023:0778-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP2 kernel was updated to receive various security and bugfixes.

- CVE-2022-36280: Fixed out-of-bounds memory access vulnerability found in vmwgfx driver (bsc#1203332).
- CVE-2022-38096: Fixed NULL-ptr deref in vmw_cmd_dx_define_query() (bsc#1203331).
- CVE-2023-0045: Fixed missing Flush IBP in ib_prctl_set (bsc#1207773).
- CVE-2023-0590: Fixed race condition in qdisc_graft() (bsc#1207795).
- CVE-2023-0597: Fixed lack of randomization of per-cpu entry area in x86/mm (bsc#1207845).
- CVE-2023-1118: Fixed a use-after-free bugs caused by ene_tx_irqsim() in media/rc (bsc#1208837).
- CVE-2023-22995: Fixed lacks of certain platform_device_put and kfree in drivers/usb/dwc3/dwc3-qcom.c (bsc#1208741).
- CVE-2023-23000: Fixed return value of tegra_xusb_find_port_node function phy/tegra (bsc#1208816).
- CVE-2023-23006: Fixed NULL vs IS_ERR checking in dr_domain_init_resources (bsc#120884).
- CVE-2023-23559: Fixed integer overflow in rndis_wlan that leads to a buffer overflow (bsc#1207051).
- CVE-2023-26545: Fixed double free in net/mpls/af_mpls.c upon an allocation failure (bsc#1208700).

The following non-security bugs were fixed:

- cifs: fix use-after-free caused by invalid pointer `hostname` (bsc#1208971).
- genirq: Provide new interfaces for affinity hints (bsc#1208153).
- mm/slub: fix panic in slab_alloc_node() (bsc#1208023).
- module: Do not wait for GOING modules (bsc#1196058, bsc#1186449, bsc#1204356, bsc#1204662).
- net: mana: Assign interrupts to CPUs based on NUMA nodes (bsc#1208153).
- net: mana: Fix IRQ name - add PCI and queue number (bsc#1207875).
- net: mana: Fix accessing freed irq affinity_hint (bsc#1208153).
- nfsd: fix use-after-free due to delegation race (bsc#1208813).
- rdma/core: Fix ib block iterator counter overflow (bsc#1207878).
- vmxnet3: move rss code block under eop descriptor (bsc#1208212).");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~150200.24.145.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~150200.24.145.1.150200.9.69.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~150200.24.145.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~150200.24.145.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~150200.24.145.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~150200.24.145.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~150200.24.145.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~150200.24.145.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~150200.24.145.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~150200.24.145.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~150200.24.145.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.3.18~150200.24.145.1", rls:"SLES15.0SP2"))) {
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
