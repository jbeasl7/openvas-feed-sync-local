# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.1019.1");
  script_cve_id("CVE-2015-8709", "CVE-2015-8812", "CVE-2015-8816", "CVE-2016-2143", "CVE-2016-2184", "CVE-2016-2384", "CVE-2016-2782", "CVE-2016-3139", "CVE-2016-3156");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-02 17:13:23 +0000 (Mon, 02 May 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:1019-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:1019-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20161019-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/816099");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/867251");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/875631");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/880007");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/943645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/944749");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/945219");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/949752");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/955308");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956084");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956852");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/957986");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/959146");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/959257");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/959463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/959709");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/960174");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/960458");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/960561");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/960629");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961257");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961500");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961516");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961588");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961658");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963193");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963746");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963765");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963827");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963960");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/964201");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/964730");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/965087");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/965199");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/965830");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/965891");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/965924");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966026");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966094");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966278");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966437");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966471");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966693");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966831");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966864");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966910");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/967047");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/967292");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/967299");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/967650");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/967651");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/967802");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/967903");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968010");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968018");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968074");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968141");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968206");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968230");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968234");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968253");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968448");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968512");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968643");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968670");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969112");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969439");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969571");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969655");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969690");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969992");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969993");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970062");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970160");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970249");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970909");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971125");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971360");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-April/001996.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2016:1019-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP1 kernel was updated to 3.12.57 to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2015-8812: A flaw was found in the CXGB3 kernel driver when
 the network was considered congested. The kernel would incorrectly
 misinterpret the congestion as an error condition and incorrectly
 free/clean up the skb. When the device would then send the skb's queued,
 these structures would be referenced and may panic the system or allow
 an attacker to escalate privileges in a use-after-free scenario. (bsc#966437)
- CVE-2015-8816: A malicious USB device could cause a kernel crash in the USB hub driver. (bnc#968010).
- CVE-2016-2143: On zSeries a fork of a large process could have caused memory corruption due to incorrect page table handling. (bnc#970504)
- CVE-2016-2184: A malicious USB device could cause a kernel crash in the alsa usb-audio driver. (bsc#971125).
- CVE-2016-2384: A malicious USB device could cause a kernel crash in the alsa usb-audio driver. (bsc#966693)
- CVE-2016-2782: A malicious USB device could cause a kernel crash in the usb visor driver. (bnc#968670).
- CVE-2016-3139: A malicious USB device could cause a kernel crash in the wacom driver. (bnc#970909).
- CVE-2016-3156: Removal of ipv4 interfaces with a large number of IP addresses was taking very long. (bsc#971360).
- CVE-2015-8709: kernel/ptrace.c in the Linux kernel mishandled uid and
 gid mappings, which allowed local users to gain privileges by establishing
 a user namespace, waiting for a root process to enter that namespace
 with an unsafe uid or gid, and then using the ptrace system call. NOTE:
 the vendor states 'there is no kernel bug here (bnc#960561).

The following non-security bugs were fixed:
- aacraid: Refresh patches.drivers/0005-aacraid-MSI-x-support.patch. (boo#970249)
- acpi: processor: Introduce apic_id in struct processor to save parsed APIC id (bsc#959463).
- alsa: rawmidi: Make snd_rawmidi_transmit() race-free (bsc#968018).
- alsa: seq: Fix leak of pool buffer at concurrent writes (bsc#968018).
- btrfs: Account data space in more proper timing: (bsc#963193).
- btrfs: Add handler for invalidate page (bsc#963193).
- btrfs: check prepare_uptodate_page() error code earlier (bnc#966910).
- btrfs: delayed_ref: Add new function to record reserved space into delayed ref (bsc#963193).
- btrfs: delayed_ref: release and free qgroup reserved at proper timing (bsc#963193).
- btrfs: extent_io: Introduce needed structure for recoding set/clear bits (bsc#963193).
- btrfs: extent_io: Introduce new function clear_record_extent_bits() (bsc#963193).
- btrfs: extent_io: Introduce new function set_record_extent_bits (bsc#963193).
- btrfs: extent-tree: Add new version of btrfs_check_data_free_space and btrfs_free_reserved_data_space (bsc#963193).
- btrfs: extent-tree: Add new version of btrfs_delalloc_reserve/release_space (bsc#963193).
- btrfs: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.12.57~60.35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debuginfo", rpm:"kernel-ec2-debuginfo~3.12.57~60.35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debugsource", rpm:"kernel-ec2-debugsource~3.12.57~60.35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.12.57~60.35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra", rpm:"kernel-ec2-extra~3.12.57~60.35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra-debuginfo", rpm:"kernel-ec2-extra-debuginfo~3.12.57~60.35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.12.57~60.35.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.12.57~60.35.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.12.57~60.35.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.12.57~60.35.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.12.57~60.35.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~3.12.57~60.35.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.12.57~60.35.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.12.57~60.35.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.12.57~60.35.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.12.57~60.35.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.12.57~60.35.1", rls:"SLES12.0SP1"))) {
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
