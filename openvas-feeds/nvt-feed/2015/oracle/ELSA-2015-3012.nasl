# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123155");
  script_cve_id("CVE-2013-7421", "CVE-2014-3610", "CVE-2014-7975", "CVE-2014-8133", "CVE-2014-8134", "CVE-2014-9644");
  script_tag(name:"creation_date", value:"2015-10-06 06:48:35 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-13 17:39:00 +0000 (Thu, 13 Aug 2020)");

  script_name("Oracle: Security Advisory (ELSA-2015-3012)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux6|OracleLinux7)");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-3012");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-3012.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dtrace-modules-3.8.13-68.el6uek, dtrace-modules-3.8.13-68.el7uek, kernel-uek' package(s) announced via the ELSA-2015-3012 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"kernel-uek
[3.8.13-68]
- ttusb-dec: buffer overflow in ioctl (Dan Carpenter) [Orabug: 20673373] {CVE-2014-8884}
- mm: Fix NULL pointer dereference in madvise(MADV_WILLNEED) support (Kirill A. Shutemov) [Orabug: 20673279] {CVE-2014-8173}
- netfilter: conntrack: disable generic tracking for known protocols (Florian Westphal) [Orabug: 20673235] {CVE-2014-8160}

[3.8.13-67]
- sparc64: Remove deprecated __GFP_NOFAIL from mdesc_kmalloc (Eric Snowberg) [Orabug: 20055909]
- x86/xen: allow privcmd hypercalls to be preempted (David Vrabel) [Orabug: 20618880]
- sched: Expose preempt_schedule_irq() (Thomas Gleixner) [Orabug: 20618880]
- xen-netfront: Fix handling packets on compound pages with skb_linearize (Zoltan Kiss) [Orabug: 19546077]
- qla2xxx: Add adapter checks for FAWWN functionality. (Saurav Kashyap) [Orabug: 20474227]
- config: enable CONFIG_MODULE_SIG_SHA512 (Guangyu Sun) [Orabug: 20611400]
- net: rds: use correct size for max unacked packets and bytes (Sasha Levin) [Orabug: 20585918]
- watchdog: w83697hf_wdt: return ENODEV if no device was found (Stanislav Kholmanskikh) [Orabug: 18122938]
- NVMe: Disable pci before clearing queue (Keith Busch) [Orabug: 20564650]

[3.8.13-66]
- bnx2fc: upgrade to 2.8.2 (Dan Duval) [Orabug: 20523502]
- bnx2i: upgrade to 2.11.0.0 (Dan Duval) [Orabug: 20523502]
- bnx2x: upgrade to 1.712.10 (Dan Duval) [Orabug: 20523502]
- cnic: upgrade to 2.721.01 (Dan Duval) [Orabug: 20523502]
- bnx2: upgrade to 2.712.01 (Dan Duval) [Orabug: 20523502]
- Update lpfc version for 10.6.61 (rkennedy) [Orabug: 20539686]
- Remove consolidated merge lines from previous patch, they require a 3.19 kernel to build with. (rkennedy) [Orabug: 20539686]
- Implement support for wire-only DIF devices (rkennedy) [Orabug: 20539686]
- lpfc: Update copyright to 2015 (rkennedy) [Orabug: 20539686]
- lpfc: Update Copyright on changed files (James Smart) [Orabug: 20539686]
- lpfc: Fix for lun discovery issue with 8Gig adapter. (rkennedy) [Orabug: 20539686]
- lpfc: Fix crash in device reset handler. (rkennedy) [Orabug: 20539686]
- lpfc: application causes OS crash when running diagnostics (rkennedy) [Orabug: 20539686]
- lpfc: Fix internal loopback failure (rkennedy) [Orabug: 20539686]
- lpfc: Fix premature release of rpi bit in bitmask (rkennedy) [Orabug: 20539686]
- lpfc: Initiator sends wrong BBCredit value for either FLOGI or FLOGI_ACC (rkennedy) [Orabug: 20539686]
- lpfc: Fix null ndlp dereference in target_reset_handler (rkennedy) [Orabug: 20539686]
- lpfc: Fix FDMI Fabric support (rkennedy) [Orabug: 20539686]
- lpfc: Fix provide host name and OS name in RSNN-NN FC-GS command (rkennedy) [Orabug: 20539686]
- lpfc: Parse the new 20G, 25G and 40G link speeds in the lpfc driver (rkennedy) [Orabug: 20539686]
- lpfc: lpfc does not support option_rom_version sysfs attribute on newer adapters (rkennedy) [Orabug: 20539686]
- lpfc: Fix setting of EQ delay Multiplier (rkennedy) [Orabug: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'dtrace-modules-3.8.13-68.el6uek, dtrace-modules-3.8.13-68.el7uek, kernel-uek' package(s) on Oracle Linux 6, Oracle Linux 7.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"dtrace-modules-3.8.13-68.el6uek", rpm:"dtrace-modules-3.8.13-68.el6uek~0.4.3~4.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~3.8.13~68.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~3.8.13~68.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~3.8.13~68.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~3.8.13~68.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~3.8.13~68.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~3.8.13~68.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"dtrace-modules-3.8.13-68.el7uek", rpm:"dtrace-modules-3.8.13-68.el7uek~0.4.3~4.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~3.8.13~68.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~3.8.13~68.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~3.8.13~68.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~3.8.13~68.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~3.8.13~68.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~3.8.13~68.el7uek", rls:"OracleLinux7"))) {
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
