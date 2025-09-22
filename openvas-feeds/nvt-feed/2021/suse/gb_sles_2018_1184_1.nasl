# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.1184.1");
  script_cve_id("CVE-2017-5754", "CVE-2018-10471", "CVE-2018-10472", "CVE-2018-7540", "CVE-2018-7541", "CVE-2018-7542", "CVE-2018-8897");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-20 14:00:15 +0000 (Wed, 20 Jun 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:1184-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:1184-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20181184-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027519");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1072834");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1080634");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1080635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1080662");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087251");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087252");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089152");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1090820");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1090822");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1090823");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-May/003988.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2018:1184-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen to version 4.9.2 fixes several issues.

This feature was added:

- Added script, udev rule and systemd service to watch for vcpu online/offline
 events in a HVM domU. They are triggered via 'xl vcpu-set domU N'

These security issues were fixed:

- CVE-2018-8897: Prevent mishandling of debug exceptions on x86 (XSA-260, bsc#1090820)
- Handle HPET timers in IO-APIC mode correctly to prevent malicious or buggy
 HVM guests from causing a hypervisor crash or potentially privilege
 escalation/information leaks (XSA-261, bsc#1090822)
- Prevent unbounded loop, induced by qemu allowing an attacker to permanently
 keep a physical CPU core busy (XSA-262, bsc#1090823)
- CVE-2018-10472: x86 HVM guest OS users (in certain configurations) were able
 to read arbitrary dom0 files via QMP live insertion of a CDROM, in conjunction
 with specifying the target file as the backing file of a snapshot
 (bsc#1089152).
- CVE-2018-10471: x86 PV guest OS users were able to cause a denial of service
 (out-of-bounds zero write and hypervisor crash) via unexpected INT 80
 processing, because of an incorrect fix for CVE-2017-5754 (bsc#1089635).
- CVE-2018-7540: x86 PV guest OS users were able to cause a denial of service
 (host OS CPU hang) via non-preemptable L3/L4 pagetable freeing (bsc#1080635).
- CVE-2018-7541: Guest OS users were able to cause a denial of service
 (hypervisor crash) or gain privileges by triggering a grant-table transition
 from v2 to v1 (bsc#1080662).
- CVE-2018-7542: x86 PVH guest OS users were able to cause a denial of service
 (NULL pointer dereference and hypervisor crash) by leveraging the mishandling
 of configurations that lack a Local APIC (bsc#1080634).

These non-security issues were fixed:

- bsc#1087252: Update built-in defaults for xenstored in stubdom, keep default
 to run xenstored as daemon in dom0
- bsc#1087251: Preserve xen-syms from xen-dbg.gz to allow processing vmcores
 with crash(1)
- bsc#1072834: Prevent unchecked MSR access error");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.9.2_04~3.29.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.9.2_04~3.29.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.9.2_04~3.29.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.9.2_04~3.29.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.9.2_04~3.29.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.9.2_04~3.29.1", rls:"SLES12.0SP3"))) {
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
