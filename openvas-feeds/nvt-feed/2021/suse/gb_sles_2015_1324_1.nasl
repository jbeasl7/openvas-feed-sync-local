# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.1324.1");
  script_cve_id("CVE-2014-9728", "CVE-2014-9729", "CVE-2014-9730", "CVE-2014-9731", "CVE-2015-1805", "CVE-2015-3212", "CVE-2015-4036", "CVE-2015-4167", "CVE-2015-4692", "CVE-2015-5364", "CVE-2015-5366");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:1324-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:1324-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20151324-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/854817");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/854824");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/858727");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/866911");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/867362");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/895814");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/903279");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/907092");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/908491");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915183");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/917630");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/918618");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/921430");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/924071");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/924526");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/926369");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/926953");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/927455");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/927697");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/927786");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/928131");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/929475");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/929696");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/929879");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/929974");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/930092");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/930399");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/930579");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/930599");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/930972");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/931124");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/931403");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/931538");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/931620");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/931860");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/931988");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/932348");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/932793");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/932897");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/932898");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/932899");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/932900");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/932967");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/933117");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/933429");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/933637");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/933896");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/933904");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/933907");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/934160");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935083");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935085");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935088");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935174");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935542");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935881");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935918");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/936012");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/936423");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/936445");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/936446");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/936502");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/936556");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/936831");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/936875");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/937032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/937087");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/937609");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/937612");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/937613");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/937616");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/938022");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/938023");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/938024");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-July/001518.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'SUSE Linux Enterprise 12 kernel' package(s) announced via the SUSE-SU-2015:1324-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 kernel was updated to 3.12.44 to receive various security and bugfixes.

These features were added:
- mpt2sas: Added Reply Descriptor Post Queue (RDPQ) Array support (bsc#854824).
- mpt3sas: Bump mpt3sas driver version to 04.100.00.00 (bsc#854817).

Following security bugs were fixed:
- CVE-2015-1805: iov overrun for failed atomic copy could have lead to
 DoS or privilege escalation (bsc#933429).
- CVE-2015-3212: A race condition in the way the Linux kernel handled
 lists of associations in SCTP sockets could have lead to list
 corruption and kernel panics (bsc#936502).
- CVE-2015-4036: DoS via memory corruption in vhost/scsi driver
 (bsc#931988).
- CVE-2015-4167: Linux kernel built with the UDF file
 system(CONFIG_UDF_FS) support was vulnerable to a crash. It occurred
 while fetching inode information from a corrupted/malicious udf file
 system image (bsc#933907).
- CVE-2015-4692: DoS via NULL pointer dereference in kvm_apic_has_events
 function (bsc#935542).
- CVE-2015-5364: Remote DoS via flood of UDP packets with invalid
 checksums (bsc#936831).
- CVE-2015-5366: Remote DoS of EPOLLET epoll applications via flood of
 UDP packets with invalid checksums (bsc#936831).

Security issues already fixed in the previous update but not referenced by CVE:
- CVE-2014-9728: Kernel built with the UDF file system(CONFIG_UDF_FS)
 support were vulnerable to a crash (bsc#933904).
- CVE-2014-9729: Kernel built with the UDF file system(CONFIG_UDF_FS)
 support were vulnerable to a crash (bsc#933904).
- CVE-2014-9730: Kernel built with the UDF file system(CONFIG_UDF_FS)
 support were vulnerable to a crash (bsc#933904).
- CVE-2014-9731: Kernel built with the UDF file system(CONFIG_UDF_FS)
 support were vulnerable to information leakage (bsc#933896).

The following non-security bugs were fixed:
- ALSA: hda - add codec ID for Skylake display audio codec (bsc#936556).
- ALSA: hda/hdmi - apply Haswell fix-ups to Skylake display codec
 (bsc#936556).
- ALSA: hda_controller: Separate stream_tag for input and output streams
 (bsc#936556).
- ALSA: hda_intel: add AZX_DCAPS_I915_POWERWELL for SKL and BSW
 (bsc#936556).
- ALSA: hda_intel: apply the Separate stream_tag for Skylake
 (bsc#936556).
- ALSA: hda_intel: apply the Separate stream_tag for Sunrise Point
 (bsc#936556).
- Btrfs: Handle unaligned length in extent_same (bsc#937609).
- Btrfs: add missing inode item update in fallocate() (bsc#938023).
- Btrfs: check pending chunks when shrinking fs to avoid corruption
 (bsc#936445).
- Btrfs: do not update mtime/ctime on deduped inodes (bsc#937616).
- Btrfs: fix block group ->space_info null pointer dereference
 (bsc#935088).
- Btrfs: fix clone / extent-same deadlocks (bsc#937612).
- Btrfs: fix deadlock with extent-same and readpage (bsc#937612).
- Btrfs: fix fsync data loss after append write (bsc#936446).
- Btrfs: fix hang during inode eviction due to concurrent ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'SUSE Linux Enterprise 12 kernel' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.12.44~52.10.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debuginfo", rpm:"kernel-ec2-debuginfo~3.12.44~52.10.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debugsource", rpm:"kernel-ec2-debugsource~3.12.44~52.10.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.12.44~52.10.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra", rpm:"kernel-ec2-extra~3.12.44~52.10.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra-debuginfo", rpm:"kernel-ec2-extra-debuginfo~3.12.44~52.10.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.12.44~52.10.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.12.44~52.10.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.12.44~52.10.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.12.44~52.10.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.12.44~52.10.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~3.12.44~52.10.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.12.44~52.10.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.12.44~52.10.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.12.44~52.10.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.12.44~52.10.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.12.44~52.10.1", rls:"SLES12.0"))) {
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
