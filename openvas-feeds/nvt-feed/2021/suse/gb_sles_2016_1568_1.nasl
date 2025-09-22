# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.1568.1");
  script_cve_id("CVE-2015-7704", "CVE-2015-7705", "CVE-2015-7974", "CVE-2016-1547", "CVE-2016-1548", "CVE-2016-1549", "CVE-2016-1550", "CVE-2016-1551", "CVE-2016-2516", "CVE-2016-2517", "CVE-2016-2518", "CVE-2016-2519", "CVE-2016-4953", "CVE-2016-4954", "CVE-2016-4955", "CVE-2016-4956", "CVE-2016-4957");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-15 13:53:53 +0000 (Tue, 15 Aug 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:1568-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:1568-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20161568-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/957226");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962960");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/977450");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/977451");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/977452");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/977455");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/977457");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/977458");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/977459");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/977461");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/977464");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979302");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979981");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/981422");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982064");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982065");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982066");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982067");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982068");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-June/002112.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp' package(s) announced via the SUSE-SU-2016:1568-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"ntp was updated to version 4.2.8p8 to fix 17 security issues.

These security issues were fixed:
- CVE-2016-4956: Broadcast interleave (bsc#982068).
- CVE-2016-2518: Crafted addpeer with hmode > 7 causes array wraparound with MATCH_ASSOC (bsc#977457).
- CVE-2016-2519: ctl_getitem() return value not always checked (bsc#977458).
- CVE-2016-4954: Processing spoofed server packets (bsc#982066).
- CVE-2016-4955: Autokey association reset (bsc#982067).
- CVE-2015-7974: NTP did not verify peer associations of symmetric keys when authenticating packets, which might allowed remote attackers to conduct impersonation attacks via an arbitrary trusted key, aka a 'skeleton key (bsc#962960).
- CVE-2016-4957: CRYPTO_NAK crash (bsc#982064).
- CVE-2016-2516: Duplicate IPs on unconfig directives will cause an assertion botch (bsc#977452).
- CVE-2016-2517: Remote configuration trustedkey/requestkey values are not properly validated (bsc#977455).
- CVE-2016-4953: Bad authentication demobilizes ephemeral associations (bsc#982065).
- CVE-2016-1547: CRYPTO-NAK DoS (bsc#977459).
- CVE-2016-1551: Refclock impersonation vulnerability, AKA: refclock-peering (bsc#977450).
- CVE-2016-1550: Improve NTP security against buffer comparison timing attacks, authdecrypt-timing, AKA: authdecrypt-timing (bsc#977464).
- CVE-2016-1548: Interleave-pivot - MITIGATION ONLY (bsc#977461).
- CVE-2016-1549: Sybil vulnerability: ephemeral association attack, AKA: ntp-sybil - MITIGATION ONLY (bsc#977451).

This release also contained improved patches for CVE-2015-7704, CVE-2015-7705, CVE-2015-7974.

These non-security issues were fixed:
- bsc#979302: Change the process name of the forking DNS worker process to avoid the impression that ntpd is started twice.
- bsc#981422: Don't ignore SIGCHILD because it breaks wait().
- bsc#979981: ntp-wait does not accept fractional seconds, so use 1 instead of 0.2 in ntp-wait.service.
- Separate the creation of ntp.keys and key #1 in it to avoid problems when upgrading installations that have the file, but no key #1, which is needed e.g. by 'rcntp addserver'.
- bsc#957226: Restrict the parser in the startup script to the first occurrance of 'keys' and 'controlkey' in ntp.conf.");

  script_tag(name:"affected", value:"'ntp' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

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

  if(!isnull(res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.8p8~46.8.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-doc", rpm:"ntp-doc~4.2.8p8~46.8.1", rls:"SLES12.0"))) {
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
