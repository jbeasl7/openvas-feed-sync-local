# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.2856.1");
  script_cve_id("CVE-2017-15588", "CVE-2017-15589", "CVE-2017-15590", "CVE-2017-15592", "CVE-2017-15593", "CVE-2017-15594", "CVE-2017-15595", "CVE-2017-5526");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-27 18:37:02 +0000 (Fri, 27 Oct 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:2856-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:2856-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20172856-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027519");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1059777");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1061076");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1061080");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1061081");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1061082");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1061084");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1061086");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1061087");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-October/003357.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2017:2856-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes several issues:

These security issues were fixed:

- CVE-2017-5526: The ES1370 audio device emulation support was vulnerable to a
 memory leakage issue allowing a privileged user inside the guest to cause a DoS
 and/or potentially crash the Qemu process on the host (bsc#1059777)
- CVE-2017-15593: Missing cleanup in the page type system allowed a malicious or
 buggy PV guest to cause DoS (XSA-242 bsc#1061084)
- CVE-2017-15592: A problem in the shadow pagetable code allowed a malicious or
 buggy HVM guest to cause DoS or cause hypervisor memory corruption potentially
 allowing the guest to escalate its privilege (XSA-243 bsc#1061086)
- CVE-2017-15594: Problematic handling of the selector fields in the Interrupt
 Descriptor Table (IDT) allowed a malicious or buggy x86 PV guest to escalate
 its privileges or cause DoS (XSA-244 bsc#1061087)
- CVE-2017-15589: Intercepted I/O write operations with less than a full machine
 word's worth of data were not properly handled, which allowed a malicious
 unprivileged x86 HVM guest to obtain sensitive information from the host or
 other guests (XSA-239 bsc#1061080)
- CVE-2017-15595: In certain configurations of linear page tables a stack overflow
 might have occurred that allowed a malicious or buggy PV guest to cause DoS and
 potentially privilege escalation and information leaks (XSA-240 bsc#1061081)
- CVE-2017-15588: Under certain conditions x86 PV guests could have caused the
 hypervisor to miss a necessary TLB flush for a page. This allowed a malicious
 x86 PV guest to access all of system memory, allowing for privilege escalation,
 DoS, and information leaks (XSA-241 bsc#1061082)
- CVE-2017-15590: Multiple issues existed with the setup of PCI MSI interrupts
 that allowed a malicious or buggy guest to cause DoS and potentially privilege
 escalation and information leaks (XSA-237 bsc#1061076)");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Server 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.4.4_24~22.54.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.4.4_24~22.54.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.4.4_24_k3.12.61_52.92~22.54.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.4.4_24~22.54.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.4.4_24~22.54.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.4.4_24~22.54.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.4.4_24~22.54.1", rls:"SLES12.0"))) {
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
