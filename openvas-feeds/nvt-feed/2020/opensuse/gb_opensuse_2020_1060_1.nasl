# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.853311");
  script_version("2025-02-28T05:38:49+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2020-11022", "CVE-2020-11023", "CVE-2020-13625", "CVE-2020-14295");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-02 16:15:00 +0000 (Wed, 02 Jun 2021)");
  script_tag(name:"creation_date", value:"2020-07-26 03:00:47 +0000 (Sun, 26 Jul 2020)");
  script_name("openSUSE: Security Advisory for cacti, (openSUSE-SU-2020:1060-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.2|openSUSELeap15\.1)");

  script_xref(name:"openSUSE-SU", value:"2020:1060-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-07/msg00067.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cacti, '
  package(s) announced via the openSUSE-SU-2020:1060-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for cacti, cacti-spine fixes the following issues:

  - cacti 1.2.13:

  * Query XSS vulnerabilities require vendor package update
  (CVE-2020-11022 / CVE-2020-11023)

  * Lack of escaping on some pages can lead to XSS exposure

  * Update PHPMailer to 6.1.6 (CVE-2020-13625)

  * SQL Injection vulnerability due to input validation failure when
  editing colors (CVE-2020-14295, boo#1173090)

  * Lack of escaping on template import can lead to XSS exposure

  - switch from cron to systemd timers (boo#1115436):
  + cacti-cron.timer
  + cacti-cron.service

  - avoid potential root escalation on systems with fs.protected_hardlinks=0
  (boo#1154087): handle directory permissions in file section instead
  of using chown during post installation

  - rewrote apache configuration to get rid of .htaccess files and
  explicitly disable directory permissions per default (only allow a
  limited, well-known set of directories)


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.2:

  zypper in -t patch openSUSE-2020-1060=1

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-1060=1");

  script_tag(name:"affected", value:"'cacti, ' package(s) on openSUSE Leap 15.2, openSUSE Leap 15.1.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"cacti", rpm:"cacti~1.2.13~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cacti-spine", rpm:"cacti-spine~1.2.13~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cacti-spine-debuginfo", rpm:"cacti-spine-debuginfo~1.2.13~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cacti-spine-debugsource", rpm:"cacti-spine-debugsource~1.2.13~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"cacti", rpm:"cacti~1.2.13~lp151.3.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cacti-spine", rpm:"cacti-spine~1.2.13~lp151.3.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cacti-spine-debuginfo", rpm:"cacti-spine-debuginfo~1.2.13~lp151.3.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cacti-spine-debugsource", rpm:"cacti-spine-debugsource~1.2.13~lp151.3.12.1", rls:"openSUSELeap15.1"))) {
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
