# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1135.1");
  script_cve_id("CVE-2016-10155", "CVE-2016-9776", "CVE-2016-9907", "CVE-2016-9911", "CVE-2016-9921", "CVE-2016-9922", "CVE-2017-2615", "CVE-2017-2620", "CVE-2017-5856", "CVE-2017-5898");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:59 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-06 14:31:12 +0000 (Thu, 06 Sep 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1135-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1135-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171135-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013285");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1014109");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1014111");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1014702");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015048");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015169");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1016779");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021129");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1023004");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1023053");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1023907");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024972");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-April/002831.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kvm' package(s) announced via the SUSE-SU-2017:1135-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kvm fixes several issues.

These security issues were fixed:

- CVE-2017-2620: In CIRRUS_BLTMODE_MEMSYSSRC mode the bitblit copy routine cirrus_bitblt_cputovideo failed to check the memory region, allowing for an out-of-bounds write that allows for privilege escalation (bsc#1024972)
- CVE-2017-2615: An error in the bitblt copy operation could have allowed a malicious guest administrator to cause an out of bounds memory access, possibly leading to information disclosure or privilege escalation (bsc#1023004)
- CVE-2016-9776: The ColdFire Fast Ethernet Controller emulator support was vulnerable to an infinite loop issue while receiving packets in 'mcf_fec_receive'. A privileged user/process inside guest could have used this issue to crash the Qemu process on the host leading to DoS (bsc#1013285)
- CVE-2016-9911: The USB EHCI Emulation support was vulnerable to a memory leakage issue while processing packet data in 'ehci_init_transfer'. A guest user/process could have used this issue to leak host memory, resulting in DoS for the host (bsc#1014111)
- CVE-2016-9907: The USB redirector usb-guest support was vulnerable to a memory leakage flaw when destroying the USB redirector in 'usbredir_handle_destroy'. A guest user/process could have used this issue to leak host memory, resulting in DoS for a host (bsc#1014109)
- CVE-2016-9921: The Cirrus CLGD 54xx VGA Emulator support was vulnerable to a divide by zero issue while copying VGA data. A privileged user inside guest could have used this flaw to crash the process instance on the host, resulting in DoS (bsc#1014702)
- CVE-2016-9922: The Cirrus CLGD 54xx VGA Emulator support was vulnerable to a divide by zero issue while copying VGA data. A privileged user inside guest could have used this flaw to crash the process instance on the host, resulting in DoS (bsc#1014702)
- CVE-2017-5898: The CCID Card device emulator support was vulnerable to an integer overflow allowing a privileged user inside the guest to crash the Qemu process resulting in DoS (bnc#1023907)
- CVE-2016-10155: The virtual hardware watchdog 'wdt_i6300esb' was vulnerable to a memory leakage issue allowing a privileged user to cause a DoS and/or potentially crash the Qemu process on the host (bsc#1021129)
- CVE-2017-5856: The MegaRAID SAS 8708EM2 Host Bus Adapter emulation support was vulnerable to a memory leakage issue allowing a privileged user to leak host memory resulting in DoS (bsc#1023053)

These non-security issues were fixed:

- Fixed various inaccuracies in cirrus vga device emulation
- Fixed virtio interface failure (bsc#1015048)
- Fixed graphical update errors introduced by previous security fix (bsc#1016779)");

  script_tag(name:"affected", value:"'kvm' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"kvm", rpm:"kvm~1.4.2~59.1", rls:"SLES11.0SP4"))) {
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
