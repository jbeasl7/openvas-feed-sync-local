# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.2859.1");
  script_cve_id("CVE-2023-1077", "CVE-2023-1249", "CVE-2023-2002", "CVE-2023-3090", "CVE-2023-3141", "CVE-2023-3159", "CVE-2023-3161", "CVE-2023-3268", "CVE-2023-3358", "CVE-2023-35788", "CVE-2023-35823", "CVE-2023-35824", "CVE-2023-35828");
  script_tag(name:"creation_date", value:"2025-02-17 04:07:12 +0000 (Mon, 17 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-23 21:19:19 +0000 (Fri, 23 Jun 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:2859-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2859-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20232859-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160435");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172073");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187829");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191731");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199046");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1200217");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205758");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209039");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209342");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210533");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210791");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211089");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211519");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211796");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212128");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212129");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212154");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212158");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212494");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212501");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212502");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212504");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212513");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212606");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212842");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2023-July/015512.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2023:2859-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2023-1077: Fixed a type confusion in pick_next_rt_entity(), that could cause memory corruption (bsc#1208600).
- CVE-2023-1249: Fixed a use-after-free flaw in the core dump subsystem that allowed a local user to crash the system (bsc#1209039).
- CVE-2023-2002: Fixed a flaw that allowed an attacker to unauthorized execution of management commands, compromising the confidentiality, integrity, and availability of Bluetooth communication (bsc#1210533).
- CVE-2023-3090: Fixed a heap out-of-bounds write in the ipvlan network driver (bsc#1212842).
- CVE-2023-3141: Fixed a use-after-free flaw in r592_remove in drivers/memstick/host/r592.c, that allowed local attackers to crash the system at device disconnect (bsc#1212129).
- CVE-2023-3159: Fixed use-after-free issue in driver/firewire in outbound_phy_packet_callback (bsc#1212128).
- CVE-2023-3161: Fixed shift-out-of-bounds in fbcon_set_font() (bsc#1212154).
- CVE-2023-3268: Fixed an out of bounds (OOB) memory access flaw in relay_file_read_start_pos in kernel/relay.c (bsc#1212502).
- CVE-2023-3358: Fixed a NULL pointer dereference flaw in the Integrated Sensor Hub (ISH) driver (bsc#1212606).
- CVE-2023-35788: Fixed an out-of-bounds write in the flower classifier code via TCA_FLOWER_KEY_ENC_OPTS_GENEVE packets in fl_set_geneve_opt in net/sched/cls_flower.c (bsc#1212504).
- CVE-2023-35823: Fixed a use-after-free flaw in saa7134_finidev in drivers/media/pci/saa7134/saa7134-core.c (bsc#1212494).
- CVE-2023-35824: Fixed a use-after-free in dm1105_remove in drivers/media/pci/dm1105/dm1105.c (bsc#1212501).
- CVE-2023-35828: Fixed a use-after-free flaw in renesas_usb3_remove in drivers/usb/gadget/udc/renesas_usb3.c (bsc#1212513).

The following non-security bugs were fixed:

- Also include kernel-docs build requirements for ALP
- Avoid unsuported tar parameter on SLE12
- Fix missing top level chapter numbers on SLE12 SP5 (bsc#1212158).
- Fix usrmerge error (boo#1211796)
- Generalize kernel-doc build requirements.
- Move obsolete KMP list into a separate file. The list of obsoleted KMPs varies per release, move it out of the spec file.
- Move setting %%build_html to config.sh
- Move setting %%split_optional to config.sh
- Move setting %%supported_modules_check to config.sh
- Move the kernel-binary conflicts out of the spec file. Thie list of conflicting packages varies per release. To reduce merge conflicts move the list out of the spec file.
- Remove obsolete rpm spec constructs defattr does not need to be specified anymore buildroot does not need to be specified anymore
- Remove usrmerge compatibility symlink in buildroot (boo#1211796).
- Trim obsolete KMP list. SLE11 is out of support, we do not need to handle upgrading from SLE11 SP1.
- cifs: do not include page data when checking signature ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.3.18~150300.59.127.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.3.18~150300.59.127.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~150300.59.127.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~150300.59.127.1.150300.18.74.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~150300.59.127.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~150300.59.127.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~150300.59.127.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~150300.59.127.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~150300.59.127.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~150300.59.127.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~150300.59.127.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~150300.59.127.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~150300.59.127.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.3.18~150300.59.127.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.3.18~150300.59.127.1", rls:"SLES15.0SP3"))) {
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
