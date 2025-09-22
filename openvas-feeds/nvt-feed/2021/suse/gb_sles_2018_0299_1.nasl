# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0299.1");
  script_cve_id("CVE-2017-15908", "CVE-2018-1049");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-08 13:16:50 +0000 (Wed, 08 Nov 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0299-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0299-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180299-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048510");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065276");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066156");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1068251");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1070428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1071558");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1074254");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1075724");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076308");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/897422");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-January/003686.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'systemd' package(s) announced via the SUSE-SU-2018:0299-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for systemd fixes several issues.

This security issue was fixed:

- CVE-2018-1049: Prevent race that can lead to DoS when using automounts (bsc#1076308).

These non-security issues were fixed:

- core: don't choke if a unit another unit triggers vanishes during reload
- delta: don't ignore PREFIX when the given argument is PREFIX/SUFFIX
- delta: extend skip logic to work on full directory paths (prefix+suffix) (bsc#1070428)
- delta: check if a prefix needs to be skipped only once
- delta: skip symlink paths when split-usr is enabled (#4591)
- sysctl: use raw file descriptor in sysctl_write (#7753)
- sd-netlink: don't take possesion of netlink fd from caller on failure (bsc#1074254)
- Fix the regexp used to detect broken by-id symlinks in /etc/crypttab
 It was missing the following case: '/dev/disk/by-id/cr_-xxx'.
- sysctl: disable buffer while writing to /proc (bsc#1071558)
- Use read_line() and LONG_LINE_MAX to read values configuration files. (bsc#1071558)
- sysctl: no need to check for eof twice
- def: add new constant LONG_LINE_MAX
- fileio: add new helper call read_line() as bounded getline() replacement
- service: Don't stop unneeded units needed by restarted service (#7526) (bsc#1066156)
- gpt-auto-generator: fix the handling of the value returned by fstab_has_fstype() in add_swap() (#6280)
- gpt-auto-generator: disable gpt auto logic for swaps if at least one is defined in fstab (bsc#897422)
- fstab-util: introduce fstab_has_fstype() helper
- fstab-generator: ignore root=/dev/nfs (#3591)
- fstab-generator: don't process root= if it happens to be 'gpt-auto' (#3452)
- virt: use XENFEAT_dom0 to detect the hardware domain (#6442, #6662) (#7581) (bsc#1048510)
- analyze: replace --no-man with --man=no in the man page (bsc#1068251)
- udev: net_setup_link: don't error out when we couldn't apply link config (#7328)
- Add missing /etc/systemd/network directory
- Fix parsing of features in detect_vm_xen_dom0 (#7890) (bsc#1048510)
- sd-bus: use -- when passing arguments to ssh (#6706)
- systemctl: make sure we terminate the bus connection first, and then close the pager (#3550)
- sd-bus: bump message queue size (bsc#1075724)
- tmpfiles: downgrade warning about duplicate line");

  script_tag(name:"affected", value:"'systemd' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0", rpm:"libsystemd0~228~150.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0-32bit", rpm:"libsystemd0-32bit~228~150.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1", rpm:"libudev1~228~150.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1-32bit", rpm:"libudev1-32bit~228~150.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd", rpm:"systemd~228~150.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-32bit", rpm:"systemd-32bit~228~150.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-bash-completion", rpm:"systemd-bash-completion~228~150.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-sysvinit", rpm:"systemd-sysvinit~228~150.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udev", rpm:"udev~228~150.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0", rpm:"libsystemd0~228~150.29.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0-32bit", rpm:"libsystemd0-32bit~228~150.29.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1", rpm:"libudev1~228~150.29.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1-32bit", rpm:"libudev1-32bit~228~150.29.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd", rpm:"systemd~228~150.29.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-32bit", rpm:"systemd-32bit~228~150.29.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-bash-completion", rpm:"systemd-bash-completion~228~150.29.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-sysvinit", rpm:"systemd-sysvinit~228~150.29.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udev", rpm:"udev~228~150.29.1", rls:"SLES12.0SP3"))) {
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
