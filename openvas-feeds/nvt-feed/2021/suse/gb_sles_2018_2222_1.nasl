# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2222.1");
  script_cve_id("CVE-2017-18344", "CVE-2017-5753", "CVE-2018-1118", "CVE-2018-13053", "CVE-2018-13405", "CVE-2018-13406", "CVE-2018-5390", "CVE-2018-9385");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:39 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-12 21:37:19 +0000 (Wed, 12 Dec 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2222-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2222-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182222-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:2222-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 kernel-azure was updated to receive various security and bugfixes.
The following security bugs were fixed:
- CVE-2018-5390 aka 'SegmentSmack': A remote attacker even with relatively
 low bandwidth could have caused lots of CPU usage by triggering the
 worst case scenario during IP and/or TCP fragment reassembly
 (bsc#1102340)
- CVE-2017-18344: The timer_create syscall implementation didn't properly
 validate input, which could have lead to out-of-bounds access. This
 allowed userspace applications to read arbitrary kernel memory in some
 setups. (bsc#1102851)
- CVE-2018-13406: An integer overflow in the uvesafb_setcmap function
 could have result in local attackers being able to crash the kernel or
 potentially elevate privileges because kmalloc_array is not used
 (bnc#1100418)
- CVE-2018-13053: The alarm_timer_nsleep function had an integer overflow
 via a large relative timeout because ktime_add_safe was not used
 (bnc#1099924)
- CVE-2018-13405: The inode_init_owner function allowed local users to
 create files with an unintended group ownership allowing attackers to
 escalate privileges by making a plain file executable and SGID
 (bnc#1100416)
- CVE-2017-5753: Systems with microprocessors utilizing speculative
 execution and branch prediction may have allowed unauthorized disclosure
 of information to an attacker with local user access via a side-channel
 analysis (bsc#1068032)
- CVE-2018-1118: Linux kernel vhost did not properly initialize memory in
 messages passed between virtual guests and the host operating system.
 This could have allowed local privileged users to read some kernel
 memory contents when reading from the /dev/vhost-net device file
 (bsc#1092472)
The following non-security bugs were fixed:
- 1wire: family module autoload fails because of upper/lower case mismatch
 (bsc#1051510)
- 8139too: Use disable_irq_nosync() in rtl8139_poll_controller()
 (networking-stable-18_05_15)
- acpi / LPSS: Add missing prv_offset setting for byt/cht PWM devices
 (bsc#1051510)
- acpi / processor: Finish making acpi_processor_ppc_has_changed() void
 (bsc#1051510)
- acpi / watchdog: properly initialize resources (bsc#1051510)
- acpi, APEI, EINJ: Subtract any matching Register Region from Trigger
 resources (bsc#1051510)
- acpi, nfit: Fix scrub idle detection (bsc#1094119)
- acpi/nfit: fix cmd_rc for acpi_nfit_ctl to always return a value
 (bsc#1051510)
- acpi: Add helper for deactivating memory region (bsc#1100132)
- ahci: Disable LPM on Lenovo 50 series laptops with a too old BIOS
 (bsc#1051510)
- alsa: hda - Handle pm failure during hotplug (bsc#1051510)
- alsa: hda/ca0132 - use ARRAY_SIZE (bsc#1051510)
- alsa: hda/ca0132: Delete pointless assignments to struct auto_pin_cfg
 fields (bsc#1051510)
- alsa: hda/ca0132: Delete redundant UNSOL event requests (bsc#1051510)
- alsa: hda/ca0132: Do not test for QUIRK_NONE (bsc#1051510)
- alsa: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Module for Public Cloud 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~5.8.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~5.8.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base-debuginfo", rpm:"kernel-azure-base-debuginfo~4.12.14~5.8.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~4.12.14~5.8.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~5.8.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~5.8.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~5.8.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~5.8.1", rls:"SLES15.0"))) {
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
