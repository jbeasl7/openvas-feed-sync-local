# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123288");
  script_cve_id("CVE-2014-2856", "CVE-2014-3537", "CVE-2014-5029", "CVE-2014-5030", "CVE-2014-5031");
  script_tag(name:"creation_date", value:"2015-10-06 11:01:47 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Oracle: Security Advisory (ELSA-2014-1388)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-1388");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-1388.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cups' package(s) announced via the ELSA-2014-1388 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1:1.4.2-67]
- Revert change to whitelist /rss/ resources, as this was not used
 upstream.

[1:1.4.2-66]
- More STR #4461 fixes from upstream: make rss feeds world-readable,
 but cachedir private.
- Fix icon display in web interface during server restart (STR #4475).

[1:1.4.2-65]
- Fixes for upstream patch for STR #4461: allow /rss/ requests for
 files we created.

[1:1.4.2-64]
- Use upstream patch for STR #4461.

[1:1.4.2-63]
- Applied upstream patch to fix CVE-2014-5029 (bug #1122600),
 CVE-2014-5030 (bug #1128764), CVE-2014-5031 (bug #1128767).
- Fix conf/log file reading for authenticated users (STR #4461).

[1:1.4.2-62]
- Fix CGI handling (STR #4454, bug #1120419).

[1:1.4.2-61]
- fix patch for CVE-2014-3537 (bug #1117794)

[1:1.4.2-60]
- CVE-2014-2856: cross-site scripting flaw (bug #1117798)
- CVE-2014-3537: insufficient checking leads to privilege escalation (bug #1117794)

[1:1.4.2-59]
- Removed package description changes.

[1:1.4.2-58]
- Applied patch to fix 'Bad request' errors as a result of adding in
 httpSetTimeout (STR #4440, also part of svn revision 9967).

[1:1.4.2-57]
- Fixed timeout issue with cupsd reading when there is no data ready
 (bug #1110045).

[1:1.4.2-56]
- Fixed synconclose patch to avoid 'too many arguments for format' warning.
- Fixed settimeout patch to include math.h for fmod declaration.

[1:1.4.2-55]
- Fixed typo preventing web interface from changing driver (bug #1104483,
 STR #3601).
- Fixed SyncOnClose patch (bug #984883).

[1:1.4.2-54]
- Use upstream patch to avoid replaying GSS credentials (bug #1040293).

[1:1.4.2-53]
- Prevent BrowsePoll problems across suspend/resume (bug #769292):
 - Eliminate indefinite wait for response (svn revision 9688).
 - Backported httpSetTimeout API function from CUPS 1.5 and use it in
 the ipp backend so that we wait indefinitely until the printer
 responds, we get a hard error, or the job is cancelled.
 - cups-polld: reconnect on error.
- Added new SyncOnClose directive to use fsync() after altering
 configuration files: defaults to 'Yes'. Adjust in cupsd.conf (bug #984883).
- Fix cupsctl man page typo (bug #1011076).
- Use more portable rpm specfile syntax for conditional php building
 (bug #988598).
- Fix SetEnv directive in cupsd.conf (bug #986495).
- Fix 'collection' attribute sending (bug #978387).
- Prevent format_log segfault (bug #971079).
- Prevent stringpool corruption (bug #884851).
- Don't crash when job queued for printer that times out (bug #855431).
- Upstream patch for broken multipart handling (bug #852846).
- Install /etc/cron.daily/cups with correct permissions (bug #1012482).");

  script_tag(name:"affected", value:"'cups' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"cups", rpm:"cups~1.4.2~67.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-devel", rpm:"cups-devel~1.4.2~67.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-libs", rpm:"cups-libs~1.4.2~67.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-lpd", rpm:"cups-lpd~1.4.2~67.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-php", rpm:"cups-php~1.4.2~67.el6", rls:"OracleLinux6"))) {
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
