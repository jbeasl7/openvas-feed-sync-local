# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.2108.1");
  script_cve_id("CVE-2015-0272", "CVE-2015-5157", "CVE-2015-5307", "CVE-2015-6252", "CVE-2015-6937", "CVE-2015-7872", "CVE-2015-7990", "CVE-2015-8104");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:10 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2015-12-28 19:44:20 +0000 (Mon, 28 Dec 2015)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:2108-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0|SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:2108-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20152108-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/777565");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/814440");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/900610");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/904348");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/904965");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/920016");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/923002");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/926007");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/926709");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/926774");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/930145");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/930788");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/932350");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/932805");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/933721");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935053");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935757");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/936118");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/938706");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/939826");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/939926");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/939955");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/940017");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/940925");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/941202");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/942204");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/942305");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/942367");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/942605");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/942688");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/942938");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/943786");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/944296");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/944831");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/944837");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/944989");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/944993");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/945691");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/945825");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/945827");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/946078");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/946309");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/947957");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/948330");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/948347");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/948521");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/949100");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/949298");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/949502");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/949706");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/949744");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/949981");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/951440");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/952084");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/952384");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/952579");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/953527");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/953980");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/954404");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-November/001700.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2015:2108-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 Service Pack 3 kernel was updated to receive various security and bugfixes.

Following security bugs were fixed:
- CVE-2015-8104: Prevent guest to host DoS caused by infinite loop in microcode via #DB exception (bsc#954404).
- CVE-2015-5307: Prevent guest to host DoS caused by infinite loop in microcode via #AC exception (bsc#953527).
- CVE-2015-7990: RDS: Verify the underlying transport exists before creating a connection, preventing possible DoS (bsc#952384).
- CVE-2015-5157: arch/x86/entry/entry_64.S in the Linux kernel on the x86_64 platform mishandled IRET faults in processing NMIs that occurred during userspace execution, which might have allowed local users to gain privileges by triggering an NMI (bsc#938706).
- CVE-2015-7872: Possible crash when trying to garbage collect an uninstantiated keyring (bsc#951440).
- CVE-2015-0272: Prevent remote DoS using IPv6 RA with bogus MTU by validating before applying it (bsc#944296).
- CVE-2015-6937: The __rds_conn_create function in net/rds/connection.c in the Linux kernel allowed local users to cause a denial of service (NULL pointer dereference and system crash) or possibly have unspecified other impact by using a socket that was not properly bound (bsc#945825).
- CVE-2015-6252: The vhost_dev_ioctl function in drivers/vhost/vhost.c in the Linux kernel allowed local users to cause a denial of service (memory consumption) via a VHOST_SET_LOG_FD ioctl call that triggered permanent file-descriptor allocation (bsc#942367).

The following non-security bugs were fixed:
- alsa: hda - Disable 64bit address for Creative HDA controllers (bsc#814440).
- btrfs: fix hang when failing to submit bio of directIO (bsc#942688).
- btrfs: fix memory corruption on failure to submit bio for direct IO (bsc#942688).
- btrfs: fix put dio bio twice when we submit dio bio fail (bsc#942688).
- dm sysfs: introduce ability to add writable attributes (bsc#904348).
- dm-snap: avoid deadock on s->lock when a read is split (bsc#939826).
- dm: do not start current request if it would have merged with the previous (bsc#904348).
- dm: impose configurable deadline for dm_request_fn merge heuristic (bsc#904348).
- drm/i915: (re)init HPD interrupt storm statistics (bsc#942938).
- drm/i915: Add HPD IRQ storm detection (v5) (bsc#942938).
- drm/i915: Add Reenable Timer to turn Hotplug Detection back on (v4) (bsc#942938).
- drm/i915: Add bit field to record which pins have received HPD events (v3) (bsc#942938).
- drm/i915: Add enum hpd_pin to intel_encoder (bsc#942938).
- drm/i915: Add messages useful for HPD storm detection debugging (v2) (bsc#942938).
- drm/i915: Avoid race of intel_crt_detect_hotplug() with HPD interrupt (bsc#942938).
- drm/i915: Convert HPD interrupts to make use of HPD pin assignment in encoders (v2) (bsc#942938).
- drm/i915: Disable HPD interrupt on pin when irq storm is detected (v3) (bsc#942938).
- drm/i915: Do not ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server for SAP Applications 11-SP3.");

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

if(release == "SLES11.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigsmp-extra", rpm:"kernel-bigsmp-extra~3.0.101~0.47.71.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~3.0.101~0.47.71.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-extra", rpm:"kernel-pae-extra~3.0.101~0.47.71.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-extra", rpm:"kernel-ppc64-extra~3.0.101~0.47.71.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-extra", rpm:"kernel-trace-extra~3.0.101~0.47.71.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-extra", rpm:"kernel-xen-extra~3.0.101~0.47.71.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigsmp", rpm:"kernel-bigsmp~3.0.101~0.47.71.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigsmp-base", rpm:"kernel-bigsmp-base~3.0.101~0.47.71.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigsmp-devel", rpm:"kernel-bigsmp-devel~3.0.101~0.47.71.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~0.47.71.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~0.47.71.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~0.47.71.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.101~0.47.71.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~0.47.71.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~0.47.71.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~0.47.71.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.101~0.47.71.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.101~0.47.71.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.101~0.47.71.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~3.0.101~0.47.71.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-base", rpm:"kernel-ppc64-base~3.0.101~0.47.71.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-devel", rpm:"kernel-ppc64-devel~3.0.101~0.47.71.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~0.47.71.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~0.47.71.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~0.47.71.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~0.47.71.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~0.47.71.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~0.47.71.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~0.47.71.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~0.47.71.1", rls:"SLES11.0SP3"))) {
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
