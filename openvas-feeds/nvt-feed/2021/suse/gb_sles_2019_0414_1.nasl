# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.0414.1");
  script_cve_id("CVE-2019-3814");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:30 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-28 14:18:30 +0000 (Thu, 28 Mar 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:0414-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:0414-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20190414-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dovecot23' package(s) announced via the SUSE-SU-2019:0414-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for dovecot23 fixes the following issues:

dovecot was updated to 2.3.3 release, bringing lots of bugfixes
(bsc#1124356).

Also the following security issue was fixed:
CVE-2019-3814: A vulnerability in Dovecot related to SSL client
 certificate authentication was fixed (bsc#1123022)

The package changes:

Updated pigeonhole to 0.5.3:
Fix assertion panic occurring when managesieve service fails to
 open INBOX while saving a Sieve script. This was caused by a lack of
 cleanup after failure.

Fix specific messages causing an assert panic with actions that compose
 a reply (e.g. vacation). With some rather weird input from the original
 message, the header folding algorithm (as used for composing the
 References header for the reply) got confused, causing the panic.

IMAP FILTER=SIEVE capability: Fix FILTER SIEVE SCRIPT command parsing.
 After finishing reading the Sieve script, the command parsing sometimes
 didn't continue with the search arguments. This is a time- critical bug
 that likely only occurs when the Sieve script is sent in the next TCP
 frame.

dovecot23 was updated to 2.3.3:
doveconf hides more secrets now in the default output.

ssl_dh setting is no longer enforced at startup. If it's not set and
 non-ECC DH key exchange happens, error is logged and client is
 disconnected.

Added log_debug= setting.

Added log_core_filter= setting.

quota-clone: Write to dict asynchronously

--enable-hardening attempts to use retpoline Spectre 2 mitigations

lmtp proxy: Support source_ip passdb extra field.

doveadm stats dump: Support more fields and output stddev by default.

push-notification: Add SSL support for OX backend.

NUL bytes in mail headers can cause truncated replies when fetched.

director: Conflicting host up/down state changes may in some rare
 situations ended up in a loop of two directors constantly
 overwriting each others' changes.

director: Fix hang/crash when multiple doveadm commands are being
 handled concurrently.

director: Fix assert-crash if doveadm disconnects too early

virtual plugin: Some searches used 100% CPU for many seconds

dsync assert-crashed with acl plugin in some situations. (bsc#1119850)

mail_attachment_detection_options=add-flags-on-save assert-crashed with
 some specific Sieve scripts.

Mail snippet generation crashed with mails containing invalid
 Content-Type:multipart header.

Log prefix ordering was different for some log lines.

quota: With noenforcing option current quota usage wasn't updated.

auth: Kerberos authentication against Samba assert-crashed.

stats clients were unnecessarily chatty with the stats server.

imapc: Fixed various assert-crashes when reconnecting to server.

lmtp, submission: Fix potential crash if client disconnects while
 handling a command.

quota: Fixed compiling with glibc-2.26 / support libtirpc.

fts-solr: Empty search values resulted in 400 Bad Request errors

fts-solr: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'dovecot23' package(s) on SUSE Linux Enterprise Module for Server Applications 15.");

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

  if(!isnull(res = isrpmvuln(pkg:"dovecot23", rpm:"dovecot23~2.3.3~4.7.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-backend-mysql", rpm:"dovecot23-backend-mysql~2.3.3~4.7.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-backend-mysql-debuginfo", rpm:"dovecot23-backend-mysql-debuginfo~2.3.3~4.7.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-backend-pgsql", rpm:"dovecot23-backend-pgsql~2.3.3~4.7.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-backend-pgsql-debuginfo", rpm:"dovecot23-backend-pgsql-debuginfo~2.3.3~4.7.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-backend-sqlite", rpm:"dovecot23-backend-sqlite~2.3.3~4.7.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-backend-sqlite-debuginfo", rpm:"dovecot23-backend-sqlite-debuginfo~2.3.3~4.7.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-debuginfo", rpm:"dovecot23-debuginfo~2.3.3~4.7.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-debugsource", rpm:"dovecot23-debugsource~2.3.3~4.7.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-devel", rpm:"dovecot23-devel~2.3.3~4.7.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts", rpm:"dovecot23-fts~2.3.3~4.7.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts-debuginfo", rpm:"dovecot23-fts-debuginfo~2.3.3~4.7.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts-lucene", rpm:"dovecot23-fts-lucene~2.3.3~4.7.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts-lucene-debuginfo", rpm:"dovecot23-fts-lucene-debuginfo~2.3.3~4.7.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts-solr", rpm:"dovecot23-fts-solr~2.3.3~4.7.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts-solr-debuginfo", rpm:"dovecot23-fts-solr-debuginfo~2.3.3~4.7.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts-squat", rpm:"dovecot23-fts-squat~2.3.3~4.7.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts-squat-debuginfo", rpm:"dovecot23-fts-squat-debuginfo~2.3.3~4.7.4", rls:"SLES15.0"))) {
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
