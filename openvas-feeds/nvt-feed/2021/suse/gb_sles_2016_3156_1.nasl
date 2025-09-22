# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.3156.1");
  script_cve_id("CVE-2016-7777", "CVE-2016-7908", "CVE-2016-7909", "CVE-2016-8576", "CVE-2016-8667", "CVE-2016-8669", "CVE-2016-8909", "CVE-2016-8910", "CVE-2016-9379", "CVE-2016-9380", "CVE-2016-9381", "CVE-2016-9382", "CVE-2016-9383", "CVE-2016-9385", "CVE-2016-9386", "CVE-2016-9637");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-25 14:49:45 +0000 (Wed, 25 Jan 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:3156-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:3156-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20163156-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000106");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003030");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1004016");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005004");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005005");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1007157");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1007160");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1009100");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1009103");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1009104");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1009107");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1009109");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1009111");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1011652");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/953518");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-December/002487.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2016:3156-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes several issues.

These security issues were fixed:

- CVE-2016-9637: ioport array overflow allowing a malicious guest administrator can escalate their privilege to that of the host (bsc#1011652)
- CVE-2016-9386: x86 null segments were not always treated as unusable allowing an unprivileged guest user program to elevate its privilege to that of the guest operating system. Exploit of this vulnerability is easy on Intel and more complicated on AMD (bsc#1009100)
- CVE-2016-9382: x86 task switch to VM86 mode was mis-handled, allowing a unprivileged guest process to escalate its privilege to that of the guest operating system on AMD hardware. On Intel hardware a malicious unprivileged guest process can crash the guest (bsc#1009103)
- CVE-2016-9385: x86 segment base write emulation lacked canonical address checks, allowing a malicious guest administrator to crash the host (bsc#1009104)
- CVE-2016-9383: The x86 64-bit bit test instruction emulation was broken, allowing a guest to modify arbitrary memory leading to arbitrary code execution (bsc#1009107)
- CVE-2016-9381: Improper processing of shared rings allowing guest administrators take over the qemu process, elevating their privilege to that of the qemu process (bsc#1009109)
- CVE-2016-9380: Delimiter injection vulnerabilities in pygrub allowed guest administrators to obtain the contents of sensitive host files or delete the files (bsc#1009111)
- CVE-2016-9379: Delimiter injection vulnerabilities in pygrub allowed guest administrators to obtain the contents of sensitive host files or delete the files (bsc#1009111)
- CVE-2016-7777: Xen did not properly honor CR0.TS and CR0.EM, which allowed local x86 HVM guest OS users to read or modify FPU, MMX, or XMM register state information belonging to arbitrary tasks on the guest by modifying an instruction while the hypervisor is preparing to emulate it (bsc#1000106)
- CVE-2016-8910: The rtl8139_cplus_transmit function in hw/net/rtl8139.c allowed local guest OS administrators to cause a denial of service (infinite loop and CPU consumption) by leveraging failure to limit the ring descriptor count (bsc#1007157)
- CVE-2016-8909: The intel_hda_xfer function in hw/audio/intel-hda.c allowed local guest OS administrators to cause a denial of service (infinite loop and CPU consumption) via an entry with the same value for buffer length and pointer position (bsc#1007160)
- CVE-2016-8667: The rc4030_write function in hw/dma/rc4030.c in allowed local guest OS administrators to cause a denial of service (divide-by-zero error and QEMU process crash) via a large interval timer reload value (bsc#1005004)
- CVE-2016-8669: The serial_update_parameters function in hw/char/serial.c allowed local guest OS administrators to cause a denial of service (divide-by-zero error and QEMU process crash) via vectors involving a value of divider greater than baud base (bsc#1005005)
- ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

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

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.4.4_05~22.25.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.4.4_05~22.25.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.4.4_05_k3.12.60_52.57~22.25.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.4.4_05~22.25.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.4.4_05~22.25.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.4.4_05~22.25.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.4.4_05~22.25.1", rls:"SLES12.0"))) {
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
