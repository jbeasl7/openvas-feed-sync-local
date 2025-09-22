# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.1351.1");
  script_cve_id("CVE-2014-9770", "CVE-2015-8842");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-05 16:53:20 +0000 (Thu, 05 May 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:1351-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:1351-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20161351-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/959886");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/960158");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963230");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/965897");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/967122");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970423");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970860");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/972612");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/972727");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/973848");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/976766");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/978275");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-May/002071.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'systemd' package(s) announced via the SUSE-SU-2016:1351-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for SystemD provides fixes and enhancements.

The following security issue has been fixed:

- Don't allow read access to journal files to users. (bsc#972612, CVE-2014-9770, CVE-2015-8842)

The following non-security issues have been fixed:

- Restore initrd-udevadm-cleanup-db.service. (bsc#978275, bsc#976766)
- Incorrect permissions set after boot on journal files. (bsc#973848)
- Exclude device-mapper from block device ownership event locking. (bsc#972727)
- Explicitly set mode for /run/log.
- Don't apply sgid and executable bit to journal files, only the directories they are contained in.
- Add ability to mask access mode by pre-existing access mode on files/directories.
- No need to pass --all if inactive is explicitly requested in list-units. (bsc#967122)
- Fix automount option and don't start associated mount unit at boot. (bsc#970423)
- Support more than just power-gpio-key. (fate#318444, bsc#970860)
- Add standard gpio power button support. (fate#318444, bsc#970860)
- Downgrade warnings about wanted unit which are not found. (bsc#960158)
- Shorten hostname before checking for trailing dot. (bsc#965897)
- Remove WorkingDirectory parameter from emergency, rescue and console-shell.service. (bsc#959886)
- Don't ship boot.udev and systemd-journald.init anymore.
- Revert 'log: honour the kernel's quiet cmdline argument'. (bsc#963230)");

  script_tag(name:"affected", value:"'systemd' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

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

  if(!isnull(res = isrpmvuln(pkg:"libgudev-1_0-0", rpm:"libgudev-1_0-0~210~70.48.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgudev-1_0-0-32bit", rpm:"libgudev-1_0-0-32bit~210~70.48.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1", rpm:"libudev1~210~70.48.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1-32bit", rpm:"libudev1-32bit~210~70.48.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd", rpm:"systemd~210~70.48.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-32bit", rpm:"systemd-32bit~210~70.48.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-bash-completion", rpm:"systemd-bash-completion~210~70.48.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-sysvinit", rpm:"systemd-sysvinit~210~70.48.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udev", rpm:"udev~210~70.48.1", rls:"SLES12.0"))) {
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
