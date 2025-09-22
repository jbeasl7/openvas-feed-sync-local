# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.0647.1");
  script_cve_id("CVE-2014-8106", "CVE-2016-10155", "CVE-2016-9101", "CVE-2016-9776", "CVE-2016-9907", "CVE-2016-9911", "CVE-2016-9921", "CVE-2016-9922", "CVE-2017-2615", "CVE-2017-2620", "CVE-2017-5579", "CVE-2017-5856", "CVE-2017-5898", "CVE-2017-5973");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:00 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-06 14:31:12 +0000 (Thu, 06 Sep 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:0647-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:0647-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20170647-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000195");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1002496");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013657");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013668");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1014490");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1014507");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015169");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1016340");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1022627");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1022871");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1023004");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024183");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024307");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024834");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1025188");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/907805");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/987002");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-March/002690.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2017:0647-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes several issues.

These security issues were fixed:

- CVE-2017-5973: A infinite loop while doing control transfer in xhci_kick_epctx allowed privileged user inside the guest to crash the host process resulting in DoS (bsc#1025188)
- CVE-2016-10155: The virtual hardware watchdog 'wdt_i6300esb' was vulnerable to a memory leakage issue allowing a privileged user to cause a DoS and/or potentially crash the Qemu process on the host (bsc#1024183)
- CVE-2017-2620: In CIRRUS_BLTMODE_MEMSYSSRC mode the bitblit copy routine cirrus_bitblt_cputovideo failed to check the memory region, allowing for an out-of-bounds write that allows for privilege escalation (bsc#1024834)
- CVE-2017-5856: The MegaRAID SAS 8708EM2 Host Bus Adapter emulation support was vulnerable to a memory leakage issue allowing a privileged user to leak host memory resulting in DoS (bsc#1024186)
- CVE-2017-5898: The CCID Card device emulator support was vulnerable to an integer overflow flaw allowing a privileged user to crash the Qemu process on the host resulting in DoS (bsc#1024307)
- CVE-2017-2615: An error in the bitblt copy operation could have allowed a malicious guest administrator to cause an out of bounds memory access, possibly leading to information disclosure or privilege escalation (bsc#1023004)
- CVE-2014-8106: A heap-based buffer overflow in the Cirrus VGA emulator allowed local guest users to execute arbitrary code via vectors related to blit regions (bsc#907805)
- CVE-2017-5579: The 16550A UART serial device emulation support was vulnerable to a memory leakage issue allowing a privileged user to cause a DoS and/or potentially crash the Qemu process on the host (bsc#1022627)
- CVE-2016-9907: The USB redirector usb-guest support was vulnerable to a memory leakage flaw when destroying the USB redirector in 'usbredir_handle_destroy'. A guest user/process could have used this issue to leak host memory, resulting in DoS for a host (bsc#1014490)
- CVE-2016-9911: The USB EHCI Emulation support was vulnerable to a memory leakage issue while processing packet data in 'ehci_init_transfer'. A guest user/process could have used this issue to leak host memory, resulting in DoS for the host (bsc#1014507)
- CVE-2016-9921: The Cirrus CLGD 54xx VGA Emulator support was vulnerable to a divide by zero issue while copying VGA data. A privileged user inside guest could have used this flaw to crash the process instance on the host, resulting in DoS (bsc#1015169)
- CVE-2016-9922: The Cirrus CLGD 54xx VGA Emulator support was vulnerable to a divide by zero issue while copying VGA data. A privileged user inside guest could have used this flaw to crash the process instance on the host, resulting in DoS (bsc#1015169)
- CVE-2016-9101: A memory leak in hw/net/eepro100.c allowed local guest OS administrators to cause a denial of service (memory consumption and QEMU process crash) by repeatedly ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.4.4_14~51.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.4.4_14~51.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.4.4_14_3.0.101_94~51.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.4.4_14_3.0.101_94~51.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.4.4_14~51.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.4.4_14~51.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.4.4_14~51.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.4.4_14~51.1", rls:"SLES11.0SP4"))) {
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
