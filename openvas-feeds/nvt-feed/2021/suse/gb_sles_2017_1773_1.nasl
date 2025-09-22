# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1773.1");
  script_cve_id("CVE-2017-9217");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-06-06 19:18:15 +0000 (Tue, 06 Jun 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1773-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1773-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171773-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1004995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1029102");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1029516");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1036873");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038865");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040258");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040614");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040942");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1043758");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982303");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-July/003005.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'systemd' package(s) announced via the SUSE-SU-2017:1773-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for systemd fixes the following issues:

Security issue fixed:

- CVE-2017-9217: resolved: Fix null pointer p->question dereferencing that could lead to resolved aborting (bsc#1040614)

The update also fixed several non-security bugs:

- core/mount: Use the '-c' flag to not canonicalize paths when calling /bin/umount
- automount: Handle expire_tokens when the mount unit changes its state (bsc#1040942)
- automount: Rework propagation between automount and mount units
- build: Make sure tmpfiles.d/systemd-remote.conf get installed when necessary
- build: Fix systemd-journal-upload installation
- basic: Detect XEN Dom0 as no virtualization (bsc#1036873)
- virt: Make sure some errors are not ignored
- fstab-generator: Do not skip Before= ordering for noauto mountpoints
- fstab-gen: Do not convert device timeout into seconds when initializing JobTimeoutSec
- core/device: Use JobRunningTimeoutSec= for device units (bsc#1004995)
- fstab-generator: Apply the _netdev option also to device units (bsc#1004995)
- job: Add JobRunningTimeoutSec for JOB_RUNNING state (bsc#1004995)
- job: Ensure JobRunningTimeoutSec= survives serialization (bsc#1004995)
- rules: Export NVMe WWID udev attribute (bsc#1038865)
- rules: Introduce disk/by-id (model_serial) symbolic links for NVMe drives
- rules: Add rules for NVMe devices
- sysusers: Make group shadow support configurable (bsc#1029516)
- core: When deserializing a unit, fully restore its cgroup state (bsc#1029102)
- core: Introduce cg_mask_from_string()/cg_mask_to_string()
- core:execute: Fix handling failures of calling fork() in exec_spawn() (bsc#1040258)
- Fix systemd-sysv-convert when a package starts shipping service units (bsc#982303)
 The database might be missing when upgrading a package which was
 shipping no sysv init scripts nor unit files (at the time --save was
 called) but the new version start shipping unit files.
- Disable group shadow support (bsc#1029516)
- Only check signature job error if signature job exists (bsc#1043758)");

  script_tag(name:"affected", value:"'systemd' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0", rpm:"libsystemd0~228~149.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0-32bit", rpm:"libsystemd0-32bit~228~149.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1", rpm:"libudev1~228~149.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1-32bit", rpm:"libudev1-32bit~228~149.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd", rpm:"systemd~228~149.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-32bit", rpm:"systemd-32bit~228~149.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-bash-completion", rpm:"systemd-bash-completion~228~149.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-sysvinit", rpm:"systemd-sysvinit~228~149.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udev", rpm:"udev~228~149.3", rls:"SLES12.0SP2"))) {
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
