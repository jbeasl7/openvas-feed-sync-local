# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122587");
  script_cve_id("CVE-2007-5495", "CVE-2007-5496");
  script_tag(name:"creation_date", value:"2015-10-08 11:48:40 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2008-0061)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2008-0061");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2008-0061.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'setroubleshoot, setroubleshoot-plugins' package(s) announced via the ELSA-2008-0061 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"setroubleshoot:
[2.0.5-3.0.1.el5]
- replace missed references to bugzilla.redhat.com with linux.oracle.com

[2.0.5-3]
- Resolve: bug #436564: socket.getsockopt() on ppc generates exception
 Fix typo in original setroubleshoot-get_credentials.patch

[2.0.5-2]
- Resolve: bug #437857: python error in system shutdown
 - Resolve: bug #436564: socket.getsockopt() on ppc generates exception

[2.0.5-1]
- Resolve: bug #431768: parser error in xmlParseDoc()

[2.0.3-3]
- Resolve: bug #429179: notification-daemon crashes when a notification is removed from the display

[2.0.3-2]
- remove libuser-python dependency
 - Related: bug #224351

[2.0.2-1]
- Resolve bug #428252: Problem with update/remove old version
 - Add code to validate xml database version, if file is incompatible it is not read,
 the next time the database is written it will be in the new version format.
 This means the database contents are not preserved across database version upgrades.
 - Remove postun trigger from spec file used to clear database between incompatible versions
 the new database version check during database read will handle this instead
 - bullet proof exit status in init script and rpm scriptlets
 - Resolve bug #247302: setroubleshoots autostart .desktop file fails to start under a KDE session
 - Resolve bug #376041: Cannot check setroubleshoot service status as non-root
 - Resolve bug #332281: remove obsolete translation
 - Resolve bug #344331: No description in gnome-session-properties
 - Resolve bug #358581: missing libuser-python dependency
 - Resolve bug #426586: Renaming translation po file from sr@Latn to sr@latin
 - Resolve bug #427260: German Translation
 - enhance the sealert man page

[2.0.1-1]
- make connection error message persist instead of timeout in browser
 - updated Brazilian Portuguese translation: Igor Pires Soares - implement uid,username checks - rpc methods now check for authenticated state - fix html handling of summary string - add 'named' messages to status bar, make sure all messages either timeout or are named - fix ordering of menus, resolves bug #427418 - add 'hide quiet' to browser view filtering, resolves bug #427421 - tweak siginfo text formatting[2.0.0-1]- prepare for v2 test release - Completed most work for version 2 of setroubleshoot, prepare for test release - import Dans changes from the mainline primarily allow_postfix_local_write_mail_spool plugin - escape html, fix siginfo.format_html(), siginfo.format_text() - add async-error signal - change identity to just username - make sure set_filter user validation works and reports error in browser - fix generation of line numbers and host when connected to audispd - add permissive notification, resolves bug #231334: Wording doesn't change for permissive mode - resolves bug #244345: avc path information incomplete - get the uid,gid when a client connects to the server - set_filter now verifies the filter is owned ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'setroubleshoot, setroubleshoot-plugins' package(s) on Oracle Linux 5.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"setroubleshoot", rpm:"setroubleshoot~2.0.5~3.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"setroubleshoot-plugins", rpm:"setroubleshoot-plugins~2.0.4~2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"setroubleshoot-server", rpm:"setroubleshoot-server~2.0.5~3.0.1.el5", rls:"OracleLinux5"))) {
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
