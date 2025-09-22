# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123470");
  script_cve_id("CVE-2013-2147", "CVE-2013-2148", "CVE-2013-2850", "CVE-2013-2893", "CVE-2013-2895", "CVE-2013-2896", "CVE-2013-2897", "CVE-2013-2898", "CVE-2013-2899", "CVE-2013-4205", "CVE-2013-4247", "CVE-2013-4270", "CVE-2013-4300", "CVE-2013-4350", "CVE-2013-6431");
  script_tag(name:"creation_date", value:"2015-10-06 11:04:14 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2014-3002)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-3002");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-3002.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dtrace-modules-3.8.13-26.el6uek, kernel-uek' package(s) announced via the ELSA-2014-3002 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[3.8.13-26.el6uek]
- spec: Don't remove crashkernel=auto setting (Jerry Snitselaar) [Orabug: 18137993]

[3.8.13-25.el6uek]
- ocfs2: fix i_mutex deadlock between aio_write and sync_file (Darrick J. Wong) [Orabug: 18068931]
- Revert 'x86, mm: Revert back good_end setting for 64bit' (Jerry Snitselaar) [Orabug: 18128986]

[3.8.13-24.el6uek]
- tg3: remove spin_lock_bh() in tg3_get_stats64() to fix dead lock (Ethan Zhao) [Orabug: 18070676]
- net/core: use GFP_NOWAIT allocation flag in rtmsg_ifinfo() to fix lockup warning (Ethan Zhao) [Orabug: 18070676]
- mptsas: do not call __mptsas_probe in kthread (Jerry Snitselaar) [Orabug: 18120337]
- config: enable CONFIG_KEXEC_AUTO_RESERVE (Jerry Snitselaar) [Orabug: 17616874]
- Btrfs: allow compressed extents to be merged during defragment (Liu Bo) [Orabug: 18098511]
- Btrfs: reset ret in record_one_backref (Josef Bacik) [Orabug: 18098511]
- Btrfs: fix a crash when running balance and defrag concurrently (Liu Bo) [Orabug: 18098511]
- Btrfs: fix a bug of snapshot-aware defrag to make it work on partial extents (Liu Bo) [Orabug: 18098511]
- Btrfs: get better concurrency for snapshot-aware defrag work (Liu Bo) [Orabug: 18098511]
- Btrfs: snapshot-aware defrag (Liu Bo) [Orabug: 18098511]
- btrfs: add cancellation points to defrag (David Sterba) [Orabug: 18098511]
- qla4xxx: Updated driver version to 5.04.00.02.06.02-uek3 (Vikas Chaudhary) [Orabug: 18103905]
- qla4xxx: Fix memory leak in qla4xxx_destroy_ddb (Vikas Chaudhary) [Orabug: 18103905]
- x86: add support for crashkernel=auto (Brian Maly)
- x86, mm: Revert back good_end setting for 64bit (Yinghai Lu) [Orabug: 17648536]

[3.8.13-23.el6uek]
- [SCSI] storvsc: avoid usage of WRITE_SAME (Olaf Hering) [Orabug: 18037923]
- Fix balloon driver to work properly with balloon_hugepages but no superpage flag (Dave McCracken)
- config: disable BUILD_DOCSRC (Jerry Snitselaar) [Orabug: 17504426]
- ext4: Fix non-O_SYNC AIO DIO unwritten extent conversion after dio finishes (Darrick J. Wong) [Orabug: 18069802]
- memcg: don't initialize kmem-cache destroying work for root caches (Andrey Vagin) [Orabug: 17791895]
- ocfs2: ocfs2 punch hole return EINVAL if the length argument in ioctl is negative (Tariq Saeed) [Orabug: 14789508]
- writeback: fix data corruption on NFS (Jan Kara) [Orabug: 16677609]
- Btrfs: handle a bogus chunk tree nicely (Josef Bacik) [Orabug: 17334825]
- Drivers: hv: Execute shutdown in a thread context (K. Y. Srinivasan) [Orabug: 18053264]
- Increase scsi_mod parameter max_report_luns to 1023. (Zhigang Wang) [Orabug: 17445498]
- NFSv4.1 Fix gdia_maxcount calculation to fit in ca_maxresponsesize (Andy Adamson) [Orabug: 17419831]
- config: disable fragile PSTORE options (Ethan Zhao) [Orabug: 17928723]
- ocfs2/o2net: o2net_listen_data_ready should do nothing if socket state is not TCP_LISTEN (Tariq Saeed) [Orabug: 17330860]
- qla4xxx: Updated driver version to 5.04.00.01.06.02-uek3 (Tej ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'dtrace-modules-3.8.13-26.el6uek, kernel-uek' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"dtrace-modules-3.8.13-26.el6uek", rpm:"dtrace-modules-3.8.13-26.el6uek~0.4.2~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtrace-modules-headers", rpm:"dtrace-modules-headers~0.4.2~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtrace-modules-provider-headers", rpm:"dtrace-modules-provider-headers~0.4.2~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~3.8.13~26.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~3.8.13~26.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~3.8.13~26.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~3.8.13~26.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~3.8.13~26.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~3.8.13~26.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-headers", rpm:"kernel-uek-headers~3.8.13~26.el6uek", rls:"OracleLinux6"))) {
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
