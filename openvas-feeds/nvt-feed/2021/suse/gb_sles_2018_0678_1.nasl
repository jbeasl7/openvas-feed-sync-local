# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0678.1");
  script_cve_id("CVE-2017-11334", "CVE-2017-15595", "CVE-2017-17563", "CVE-2017-17564", "CVE-2017-17565", "CVE-2017-17566", "CVE-2017-18030", "CVE-2017-5715", "CVE-2017-5753", "CVE-2017-5754", "CVE-2017-5898", "CVE-2018-5683", "CVE-2018-7540", "CVE-2018-7541");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:47 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-17 00:17:05 +0000 (Sat, 17 Mar 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0678-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0678-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180678-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024307");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030144");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1061081");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1068032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1070158");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1070159");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1070160");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1070163");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1074562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076116");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076180");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1080635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1080662");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-March/003814.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2018:0678-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes several issues.

These security issues were fixed:

- CVE-2017-5753, CVE-2017-5715, CVE-2017-5754: Prevent information leaks via
 side effects of speculative execution, aka 'Spectre' and 'Meltdown' attacks
 (bsc#1074562, bsc#1068032)
- CVE-2018-5683: The vga_draw_text function allowed local OS guest privileged
 users to cause a denial of service (out-of-bounds read and QEMU process crash)
 by leveraging improper memory address validation (bsc#1076116).
- CVE-2017-18030: The cirrus_invalidate_region function allowed local OS guest
 privileged users to cause a denial of service (out-of-bounds array access and
 QEMU process crash) via vectors related to negative pitch (bsc#1076180).
- CVE-2017-15595: x86 PV guest OS users were able to cause a DoS (unbounded
 recursion, stack consumption, and hypervisor crash) or possibly gain privileges
 via crafted page-table stacking (bsc#1061081)
- CVE-2017-17566: Prevent PV guest OS users to cause a denial of service (host
 OS crash) or gain host OS privileges in shadow mode by mapping a certain
 auxiliary page (bsc#1070158).
- CVE-2017-17563: Prevent guest OS users to cause a denial of service (host OS
 crash) or gain host OS privileges by leveraging an incorrect mask for
 reference-count overflow checking in shadow mode (bsc#1070159).
- CVE-2017-17564: Prevent guest OS users to cause a denial of service (host OS
 crash) or gain host OS privileges by leveraging incorrect error handling for
 reference counting in shadow mode (bsc#1070160).
- CVE-2017-17565: Prevent PV guest OS users to cause a denial of service (host
 OS crash) if shadow mode and log-dirty mode are in place, because of an
 incorrect assertion related to M2P (bsc#1070163).
- Added missing intermediate preemption checks for guest requesting removal of
 memory. This allowed malicious guest administrator to cause denial of service
 due to the high cost of this operation (bsc#1080635).
- Because of XEN not returning the proper error messages when transitioning
 grant tables from v2 to v1 a malicious guest was able to cause DoS or
 potentially allowed for privilege escalation as well as information leaks
 (bsc#1080662).
- CVE-2017-5898: The CCID Card device emulator support was vulnerable to an
 integer overflow flaw allowing a privileged user to crash the Qemu process on
 the host resulting in DoS (bsc#1024307)
- Unprivileged domains could have issued well-timed writes to xenstore which
 conflict with transactions to stall progress of the control domain or driver
 domain, possibly leading to DoS (bsc#1030144, XSA-206).");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Server 11-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.2.5_21~45.19.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.2.5_21~45.19.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-pdf", rpm:"xen-doc-pdf~4.2.5_21~45.19.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.2.5_21_3.0.101_0.47.106.14~45.19.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.2.5_21_3.0.101_0.47.106.14~45.19.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.2.5_21~45.19.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.2.5_21~45.19.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.2.5_21~45.19.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.2.5_21~45.19.1", rls:"SLES11.0SP3"))) {
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
