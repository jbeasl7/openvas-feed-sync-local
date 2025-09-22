# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2014.1318.1");
  script_cve_id("CVE-2013-4344", "CVE-2013-4540", "CVE-2014-2599", "CVE-2014-3967", "CVE-2014-3968", "CVE-2014-4021", "CVE-2014-7154", "CVE-2014-7155", "CVE-2014-7156", "CVE-2014-7188");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:15 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2014:1318-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2014:1318-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2014/suse-su-20141318-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Xen' package(s) announced via the SUSE-SU-2014:1318-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 Service Pack 3 Xen package was updated to fix various bugs and security issues.

The following security issues have been fixed:

 * XSA-108: CVE-2014-7188: Improper MSR range used for x2APIC emulation
 (bnc#897657)
 * XSA-106: CVE-2014-7156: Missing privilege level checks in x86
 emulation of software interrupts (bnc#895802)
 * XSA-105: CVE-2014-7155: Missing privilege level checks in x86 HLT,
 LGDT, LIDT, and LMSW emulation (bnc#895799)
 * XSA-104: CVE-2014-7154: Race condition in HVMOP_track_dirty_vram
 (bnc#895798)
 * XSA-100: CVE-2014-4021: Hypervisor heap contents leaked to guests
 (bnc#880751)
 * XSA-96: CVE-2014-3967, CVE-2014-3968: Vulnerabilities in HVM MSI
 injection (bnc#878841)
 * XSA-89: CVE-2014-2599: HVMOP_set_mem_access is not preemptible
 (bnc#867910)
 * XSA-65: CVE-2013-4344: qemu SCSI REPORT LUNS buffer overflow
 (bnc#842006)
 * CVE-2013-4540: qemu: zaurus: buffer overrun on invalid state load
 (bnc#864801)

The following non-security issues have been fixed:

 * xend: Fix netif convertToDeviceNumber for running domains
 (bnc#891539)
 * Installing SLES12 as a VM on SLES11 SP3 fails because of btrfs in
 the VM (bnc#882092)
 * XEN kernel panic do_device_not_available() (bnc#881900)
 * Boot Failure with xen kernel in UEFI mode with error 'No memory for
 trampoline' (bnc#833483)
 * SLES 11 SP3 vm-install should get RHEL 7 support when released
 (bnc#862608)
 * SLES 11 SP3 XEN kiso version cause softlockup on 8 blades npar(480
 cpu) (bnc#858178)
 * Local attach support for PHY backends using scripts
 local_attach_support_for_phy.patch (bnc#865682)
 * Improve multipath support for npiv devices block-npiv (bnc#798770)

Security Issues:

 * CVE-2013-4344
 * CVE-2013-4540
 * CVE-2014-2599
 * CVE-2014-3967
 * CVE-2014-3968
 * CVE-2014-4021
 * CVE-2014-7154
 * CVE-2014-7155
 * CVE-2014-7156
 * CVE-2014-7188");

  script_tag(name:"affected", value:"'Xen' package(s) on SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Software Development Kit 11-SP3.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.2.4_04~0.9.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.2.4_04~0.9.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-pdf", rpm:"xen-doc-pdf~4.2.4_04~0.9.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.2.4_04_3.0.101_0.40~0.9.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.2.4_04_3.0.101_0.40~0.9.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.2.4_04~0.9.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.2.4_04~0.9.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.2.4_04~0.9.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.2.4_04~0.9.1", rls:"SLES11.0SP3"))) {
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
