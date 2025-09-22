# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.0353.1");
  script_cve_id("CVE-2020-1712");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-10 15:42:07 +0000 (Fri, 10 Apr 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:0353-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:0353-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20200353-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106383");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127557");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133495");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1139459");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140631");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150595");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151377");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151506");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154043");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154948");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155574");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1156482");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159814");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1162108");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-February/006464.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'systemd' package(s) announced via the SUSE-SU-2020:0353-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for systemd provides the following fixes:

- CVE-2020-1712 (bsc#bsc#1162108)
 Fix a heap use-after-free vulnerability, when asynchronous
 Polkit queries were performed while handling Dbus messages. A local
 unprivileged attacker could have abused this flaw to crash systemd services or
 potentially execute code and elevate their privileges, by sending specially
 crafted Dbus messages.
- sd-bus: Deal with cookie overruns. (bsc#1150595)
- rules: Add by-id symlinks for persistent memory. (bsc#1140631)
- Drop the old fds used for logging and reopen them in the sub process before doing any
 new logging. (bsc#1154948)
- Fix warnings thrown during package installation (bsc#1154043)
- Fix for systemctl hanging by restart. (bsc#1139459)
- man: mention that alias names are only effective after 'systemctl enable'. (bsc#1151377)
- ask-password: improve log message when inotify limit is reached. (bsc#1155574)
- udevd: wait for workers to finish when exiting. (bsc#1106383)
- core: fragments of masked units ought not be considered for NeedDaemonReload. (bsc#1156482)
- udev: fix 'NULL' deref when executing rules. (bsc#1151506)
- Introduce function for reading virtual files in 'sysfs' and 'procfs'. (bsc#1133495, bsc#1159814)");

  script_tag(name:"affected", value:"'systemd' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0", rpm:"libsystemd0~228~157.9.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0-32bit", rpm:"libsystemd0-32bit~228~157.9.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1", rpm:"libudev1~228~157.9.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1-32bit", rpm:"libudev1-32bit~228~157.9.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd", rpm:"systemd~228~157.9.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-32bit", rpm:"systemd-32bit~228~157.9.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-bash-completion", rpm:"systemd-bash-completion~228~157.9.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-sysvinit", rpm:"systemd-sysvinit~228~157.9.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udev", rpm:"udev~228~157.9.1", rls:"SLES12.0SP5"))) {
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
