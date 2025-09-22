# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2475.1");
  script_cve_id("CVE-2016-7796");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-10-13 17:16:59 +0000 (Thu, 13 Oct 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2475-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2475-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162475-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000435");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1001765");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/954374");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970293");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982210");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982211");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982251");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/987173");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/987857");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/990074");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/996269");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-October/002318.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'systemd' package(s) announced via the SUSE-SU-2016:2475-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for systemd fixes the following security issue:

- CVE-2016-7796: A zero-length message received over systemd's notification socket
 could make manager_dispatch_notify_fd() return an error and, as a side effect,
 disable the notification handler completely. As the notification socket is
 world-writable, this could have allowed a local user to perform a denial-of-service
 attack against systemd. (bsc#1001765)

Additionally, the following non-security fixes are included:

- Fix HMAC calculation when appending a data object to journal. (bsc#1000435)
- Never accept file descriptors from file systems with mandatory locking enabled.
 (bsc#954374)
- Do not warn about missing install info with 'preset'. (bsc#970293)
- Save /run/systemd/users/UID before starting user@.service. (bsc#996269)
- Make sure that /var/lib/systemd/sysv-convert/database is always initialized.
 (bsc#982211)
- Remove daylight saving time handling and tzfile parser. (bsc#990074)
- Make sure directory watch is started before cryptsetup. (bsc#987173)
- Introduce sd_pid_notify() and sd_pid_notifyf() APIs. (bsc#987857)
- Set KillMode=mixed for our daemons that fork worker processes.
- Add nosuid and nodev options to tmp.mount.
- Don't start console-getty.service when /dev/console is missing. (bsc#982251)
- Correct segmentation fault in udev/path_id due to missing NULL check. (bsc#982210)");

  script_tag(name:"affected", value:"'systemd' package(s) on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

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

  if(!isnull(res = isrpmvuln(pkg:"libgudev-1_0-0", rpm:"libgudev-1_0-0~210~70.58.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgudev-1_0-0-32bit", rpm:"libgudev-1_0-0-32bit~210~70.58.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1", rpm:"libudev1~210~70.58.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1-32bit", rpm:"libudev1-32bit~210~70.58.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd", rpm:"systemd~210~70.58.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-32bit", rpm:"systemd-32bit~210~70.58.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-bash-completion", rpm:"systemd-bash-completion~210~70.58.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-sysvinit", rpm:"systemd-sysvinit~210~70.58.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udev", rpm:"udev~210~70.58.1", rls:"SLES12.0"))) {
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
