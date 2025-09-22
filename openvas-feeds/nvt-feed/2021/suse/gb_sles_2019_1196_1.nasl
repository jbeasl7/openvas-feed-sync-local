# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.1196.1");
  script_cve_id("CVE-2014-9116", "CVE-2018-14349", "CVE-2018-14350", "CVE-2018-14351", "CVE-2018-14352", "CVE-2018-14353", "CVE-2018-14354", "CVE-2018-14355", "CVE-2018-14356", "CVE-2018-14357", "CVE-2018-14358", "CVE-2018-14359", "CVE-2018-14360", "CVE-2018-14361", "CVE-2018-14362", "CVE-2018-14363");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-12 16:19:40 +0000 (Wed, 12 Sep 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:1196-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:1196-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20191196-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1061343");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094717");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101566");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101567");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101568");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101569");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101570");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101571");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101573");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101576");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101577");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101578");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101581");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101582");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101583");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101588");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101589");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/980830");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982129");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/986534");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-May/005432.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mutt' package(s) announced via the SUSE-SU-2019:1196-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for mutt fixes the following issues:

Security issues fixed:

- bsc#1101428: Mutt 1.10.1 security release update.
- CVE-2018-14351: Fix imap/command.c that mishandles long IMAP status mailbox literal count size (bsc#1101583).
- CVE-2018-14353: Fix imap_quote_string in imap/util.c that has an integer underflow (bsc#1101581).
- CVE-2018-14362: Fix pop.c that does not forbid characters that may have unsafe interaction with message-cache pathnames (bsc#1101567).
- CVE-2018-14354: Fix arbitrary command execution from remote IMAP servers via backquote characters (bsc#1101578).
- CVE-2018-14352: Fix imap_quote_string in imap/util.c that does not leave room for quote characters (bsc#1101582).
- CVE-2018-14356: Fix pop.c that mishandles a zero-length UID (bsc#1101576).
- CVE-2018-14355: Fix imap/util.c that mishandles '..' directory traversal in a mailbox name (bsc#1101577).
- CVE-2018-14349: Fix imap/command.c that mishandles a NO response without a message (bsc#1101589).
- CVE-2018-14350: Fix imap/message.c that has a stack-based buffer overflow for a FETCH response with along INTERNALDATE field (bsc#1101588).
- CVE-2018-14363: Fix newsrc.c that does not properlyrestrict '/' characters that may have unsafe interaction with cache pathnames (bsc#1101566).
- CVE-2018-14359: Fix buffer overflow via base64 data (bsc#1101570).
- CVE-2018-14358: Fix imap/message.c that has a stack-based buffer overflow for a FETCH response with along RFC822.SIZE field (bsc#1101571).
- CVE-2018-14360: Fix nntp_add_group in newsrc.c that has a stack-based buffer overflow because of incorrect sscanf usage (bsc#1101569).
- CVE-2018-14357: Fix that remote IMAP servers are allowed to execute arbitrary commands via backquote characters (bsc#1101573).
- CVE-2018-14361: Fix that nntp.c proceeds even if memory allocation fails for messages data (bsc#1101568).

Bug fixes:

- mutt reports as neomutt and incorrect version (bsc#1094717)
- No sidebar available in mutt 1.6.1 from Tumbleweed snapshot 20160517 (bsc#980830)
- mutt-1.6.1 unusable when built with --enable-sidebar (bsc#982129)
- (neo)mutt displaying times in Zulu time (bsc#1061343)
- mutt unconditionally segfaults when displaying a message (bsc#986534)");

  script_tag(name:"affected", value:"'mutt' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"mutt", rpm:"mutt~1.10.1~55.6.1", rls:"SLES12.0SP3"))) {
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
