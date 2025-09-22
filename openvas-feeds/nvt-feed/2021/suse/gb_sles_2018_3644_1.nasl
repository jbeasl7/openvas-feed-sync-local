# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.3644.1");
  script_cve_id("CVE-2018-15686", "CVE-2018-15688");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:34 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-31 18:30:19 +0000 (Mon, 31 Jan 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:3644-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:3644-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20183644-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'systemd' package(s) announced via the SUSE-SU-2018:3644-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for systemd fixes the following issues:

Security issues fixed:
CVE-2018-15688: A buffer overflow vulnerability in the dhcp6 client of
 systemd allowed a malicious dhcp6 server to overwrite heap memory in
 systemd-networkd. (bsc#1113632)

CVE-2018-15686: A vulnerability in unit_deserialize of systemd allows an
 attacker to supply arbitrary state across systemd re-execution via
 NotifyAccess. This can be used to improperly influence systemd execution
 and possibly lead to root privilege escalation. (bsc#1113665)

Non security issues fixed:
dhcp6: split assert_return() to be more debuggable when hit

core: skip unit deserialization and move to the next one when
 unit_deserialize() fails

core: properly handle deserialization of unknown unit types (#6476)

core: don't create Requires for workdir if 'missing ok' (bsc#1113083)

logind: use manager_get_user_by_pid() where appropriate

logind: rework manager_get_{user<pipe>session}_by_pid() a bit

login: fix user@.service case, so we don't allow nested sessions (#8051)
 (bsc#1112024)

core: be more defensive if we can't determine per-connection socket peer
 (#7329)

core: introduce systemd.early_core_pattern= kernel cmdline option

core: add missing 'continue' statement

core/mount: fstype may be NULL

journald: don't ship systemd-journald-audit.socket (bsc#1109252)

core: make 'tmpfs' dependencies on swapfs a 'default' dep, not an
 'implicit' (bsc#1110445)

mount: make sure we unmount tmpfs mounts before we deactivate swaps
 (#7076)

detect-virt: do not try to read all of /proc/cpuinfo (bsc#1109197)

emergency: make sure console password agents don't interfere with the
 emergency shell

man: document that 'nofail' also has an effect on ordering

journald: take leading spaces into account in syslog_parse_identifier

journal: do not remove multiple spaces after identifier in syslog message

syslog: fix segfault in syslog_parse_priority()

journal: fix syslog_parse_identifier()

install: drop left-over debug message (#6913)

Ship systemd-sysv-install helper via the main package This script was
 part of systemd-sysvinit sub-package but it was wrong since
 systemd-sysv-install is a script used to redirect enable/disable
 operations to chkconfig when the unit targets are sysv init scripts.
 Therefore it's never been a SySV init tool.

Add udev.no-partlabel-links kernel command-line option. This option can
 be used to disable the generation of the by-partlabel symlinks
 regardless of the name used. (bsc#1089761)

man: SystemMaxUse= clarification in journald.conf(5). (bsc#1101040)

systemctl: load unit if needed in 'systemctl is-active' (bsc#1102908)

core: don't freeze OnCalendar= timer units when the clock goes back a
 lot (bsc#1090944)

Enable or disable machines.target according to the presets (bsc#1107941)

cryptsetup: add support for sector-size= option (fate#325697)

nspawn: always use permission mode 555 for /sys ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'systemd' package(s) on SUSE Linux Enterprise Module for Basesystem 15, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0", rpm:"libsystemd0~234~24.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0-32bit", rpm:"libsystemd0-32bit~234~24.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0-32bit-debuginfo", rpm:"libsystemd0-32bit-debuginfo~234~24.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0-debuginfo", rpm:"libsystemd0-debuginfo~234~24.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev-devel", rpm:"libudev-devel~234~24.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1", rpm:"libudev1~234~24.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1-32bit", rpm:"libudev1-32bit~234~24.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1-32bit-debuginfo", rpm:"libudev1-32bit-debuginfo~234~24.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1-debuginfo", rpm:"libudev1-debuginfo~234~24.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd", rpm:"systemd~234~24.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-32bit", rpm:"systemd-32bit~234~24.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-32bit-debuginfo", rpm:"systemd-32bit-debuginfo~234~24.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-bash-completion", rpm:"systemd-bash-completion~234~24.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-container", rpm:"systemd-container~234~24.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-container-debuginfo", rpm:"systemd-container-debuginfo~234~24.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-coredump", rpm:"systemd-coredump~234~24.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-coredump-debuginfo", rpm:"systemd-coredump-debuginfo~234~24.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-debuginfo", rpm:"systemd-debuginfo~234~24.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-debugsource", rpm:"systemd-debugsource~234~24.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-devel", rpm:"systemd-devel~234~24.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-sysvinit", rpm:"systemd-sysvinit~234~24.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udev", rpm:"udev~234~24.15.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udev-debuginfo", rpm:"udev-debuginfo~234~24.15.1", rls:"SLES15.0"))) {
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
