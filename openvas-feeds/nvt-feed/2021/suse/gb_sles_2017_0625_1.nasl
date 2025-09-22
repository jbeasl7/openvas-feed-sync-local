# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.0625.1");
  script_cve_id("CVE-2016-10028", "CVE-2016-10029", "CVE-2016-10155", "CVE-2016-9921", "CVE-2016-9922", "CVE-2017-2615", "CVE-2017-2620", "CVE-2017-5525", "CVE-2017-5526", "CVE-2017-5552", "CVE-2017-5578", "CVE-2017-5667", "CVE-2017-5856", "CVE-2017-5857", "CVE-2017-5898");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-06 14:31:12 +0000 (Thu, 06 Sep 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:0625-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:0625-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20170625-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1014702");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015169");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1016779");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1017081");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1017084");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020491");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020589");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020928");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021129");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021195");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021481");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1022541");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1023004");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1023053");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1023073");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1023907");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024972");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1026583");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/977027");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-March/002684.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu' package(s) announced via the SUSE-SU-2017:0625-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for qemu fixes several issues.

These security issues were fixed:

- CVE-2017-5898: The CCID Card device emulator support was vulnerable to an integer overflow flaw allowing a privileged user to crash the Qemu process on the host resulting in DoS (bsc#1023907).
- CVE-2017-5857: The Virtio GPU Device emulator support was vulnerable to a host memory leakage issue allowing a guest user to leak host memory resulting in DoS (bsc#1023073).
- CVE-2017-2620: In CIRRUS_BLTMODE_MEMSYSSRC mode the bitblit copy routine cirrus_bitblt_cputovideo failed to check the memory region, allowing for an out-of-bounds write that allows for privilege escalation (bsc#1024972)
- CVE-2017-2615: An error in the bitblt copy operation could have allowed a malicious guest administrator to cause an out of bounds memory access, possibly leading to information disclosure or privilege escalation (bsc#1023004)
- CVE-2017-5856: The MegaRAID SAS 8708EM2 Host Bus Adapter emulation support was vulnerable to a memory leakage issue allowing a privileged user to leak host memory resulting in DoS (bsc#1023053)
- CVE-2016-9921: The Cirrus CLGD 54xx VGA Emulator support was vulnerable to a divide by zero issue while copying VGA data. A privileged user inside guest could have used this flaw to crash the process instance on the host, resulting in DoS (bsc#1014702)
- CVE-2016-9922: The Cirrus CLGD 54xx VGA Emulator support was vulnerable to a divide by zero issue while copying VGA data. A privileged user inside guest could have used this flaw to crash the process instance on the host, resulting in DoS (bsc#1014702)
- CVE-2016-10029: The Virtio GPU Device emulator support was vulnerable to an OOB read issue allowing a guest user to crash the Qemu process instance resulting in Dos (bsc#1017081).
- CVE-2016-10028: The Virtio GPU Device emulator support was vulnerable to an out of bounds memory access issue allowing a guest user to crash the Qemu process instance on a host, resulting in DoS (bsc#1017084).
- CVE-2016-10155: The virtual hardware watchdog 'wdt_i6300esb' was vulnerable to a memory leakage issue allowing a privileged user to cause a DoS and/or potentially crash the Qemu process on the host (bsc#1021129)
- CVE-2017-5552: The Virtio GPU Device emulator support was vulnerable to a memory leakage issue allowing a guest user to leak host memory resulting in DoS (bsc#1021195).
- CVE-2017-5578: The Virtio GPU Device emulator support was vulnerable to a memory leakage issue allowing a guest user to leak host memory resulting in DoS (bsc#1021481).
- CVE-2017-5526: The ES1370 audio device emulation support was vulnerable to a memory leakage issue allowing a privileged user inside the guest to cause a DoS and/or potentially crash the Qemu process on the host (bsc#1020589).
- CVE-2017-5525: The ac97 audio device emulation support was vulnerable to a memory leakage issue allowing a privileged user inside the ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'qemu' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"qemu", rpm:"qemu~2.6.2~41.9.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-arm", rpm:"qemu-arm~2.6.2~41.9.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-curl", rpm:"qemu-block-curl~2.6.2~41.9.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-rbd", rpm:"qemu-block-rbd~2.6.2~41.9.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-ssh", rpm:"qemu-block-ssh~2.6.2~41.9.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~2.6.2~41.9.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ipxe", rpm:"qemu-ipxe~1.0.0~41.9.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~2.6.2~41.9.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-lang", rpm:"qemu-lang~2.6.2~41.9.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ppc", rpm:"qemu-ppc~2.6.2~41.9.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-s390", rpm:"qemu-s390~2.6.2~41.9.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-seabios", rpm:"qemu-seabios~1.9.1~41.9.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-sgabios", rpm:"qemu-sgabios~8~41.9.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-tools", rpm:"qemu-tools~2.6.2~41.9.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-vgabios", rpm:"qemu-vgabios~1.9.1~41.9.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-x86", rpm:"qemu-x86~2.6.2~41.9.1", rls:"SLES12.0SP2"))) {
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
