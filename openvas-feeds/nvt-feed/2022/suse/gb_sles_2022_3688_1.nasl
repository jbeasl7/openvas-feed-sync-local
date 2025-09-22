# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3688.1");
  script_cve_id("CVE-2022-2503", "CVE-2022-3239", "CVE-2022-3303", "CVE-2022-41218", "CVE-2022-41848");
  script_tag(name:"creation_date", value:"2022-10-24 04:59:11 +0000 (Mon, 24 Oct 2022)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-21 18:07:55 +0000 (Wed, 21 Sep 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3688-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3688-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223688-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201309");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202385");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202677");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202960");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203552");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203769");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203987");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-October/012601.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:3688-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 kernel was updated.

The following security bugs were fixed:

- CVE-2022-3303: Fixed a race condition in the sound subsystem due to improper locking (bnc#1203769).
- CVE-2022-41218: Fixed an use-after-free caused by refcount races in drivers/media/dvb-core/dmxdev.c (bnc#1202960).
- CVE-2022-3239: Fixed an use-after-free in the video4linux driver that could lead a local user to able to crash the system or escalate their privileges (bnc#1203552).
- CVE-2022-41848: Fixed a race condition and resultant use-after-free if a physically proximate attacker removes a PCMCIA device while calling ioctl (bnc#1203987).
- CVE-2022-2503: Fixed a bug in dm-verity, device-mapper table reloads allowed users with root privileges to switch out the target with an equivalent dm-linear target and bypass verification till reboot. This allowed root to bypass LoadPin and can be used to load untrusted and unverified kernel modules and firmware, which implies arbitrary kernel execution and persistence for peripherals that do not verify firmware updates (bnc#1202677).

The following non-security bugs were fixed:

- dtb: Do not include sources in src.rpm - refer to kernel-source Same as other kernel binary packages there is no need to carry duplicate sources in dtb packages.
- net: mana: Add rmb after checking owner bits (git-fixes).
- net: mana: Add the Linux MANA PF driver (bug#1201309, jsc#PED-529).
- x86/bugs: Reenable retbleed=off While for older kernels the return thunks are statically built in and cannot be dynamically patched out, retbleed=off should still be possible to do so that the mitigation can still be disabled on Intel who do not use the return thunks but IBRS.");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP Applications 15.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~150000.150.104.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~150000.150.104.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~150000.150.104.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~150000.150.104.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~150000.150.104.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~4.12.14~150000.150.104.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~150000.150.104.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~4.12.14~150000.150.104.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~150000.150.104.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~150000.150.104.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-base", rpm:"kernel-vanilla-base~4.12.14~150000.150.104.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~4.12.14~150000.150.104.1", rls:"SLES15.0"))) {
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
