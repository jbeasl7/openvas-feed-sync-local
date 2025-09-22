# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.1311.1");
  script_cve_id("CVE-2015-5194", "CVE-2015-5219", "CVE-2015-5300", "CVE-2015-7691", "CVE-2015-7692", "CVE-2015-7701", "CVE-2015-7702", "CVE-2015-7703", "CVE-2015-7704", "CVE-2015-7705", "CVE-2015-7848", "CVE-2015-7849", "CVE-2015-7850", "CVE-2015-7851", "CVE-2015-7852", "CVE-2015-7853", "CVE-2015-7854", "CVE-2015-7855", "CVE-2015-7871", "CVE-2015-7973", "CVE-2015-7974", "CVE-2015-7975", "CVE-2015-7976", "CVE-2015-7977", "CVE-2015-7978", "CVE-2015-7979", "CVE-2015-8138", "CVE-2015-8139", "CVE-2015-8140", "CVE-2015-8158");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:06 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-15 14:19:55 +0000 (Tue, 15 Aug 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:1311-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2|SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:1311-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20161311-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/782060");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/784760");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/905885");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/910063");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/916617");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/920183");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/920238");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/926510");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/936327");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/937837");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/942441");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/942587");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/943216");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/943218");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/944300");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/946386");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/951351");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/951559");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/951608");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/951629");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/954982");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956773");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962318");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962784");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962802");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962960");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962966");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962970");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962988");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962994");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962997");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963000");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963002");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/975496");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/975981");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-May/002064.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp' package(s) announced via the SUSE-SU-2016:1311-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This network time protocol server ntp was updated to 4.2.8p6 to fix the following issues:

Also yast2-ntp-client was updated to match some sntp syntax changes. (bsc#937837)

Major functional changes:
- The 'sntp' commandline tool changed its option handling in a major way.
- 'controlkey 1' is added during update to ntp.conf to allow sntp to work.
- The local clock is being disabled during update.
- ntpd is no longer running chrooted.


Other functional changes:
- ntp-signd is installed.
- 'enable mode7' can be added to the configuration to allow ntdpc to work as compatibility mode option.
- 'kod' was removed from the default restrictions.
- SHA1 keys are used by default instead of MD5 keys.

These security issues were fixed:
- CVE-2015-5219: An endless loop due to incorrect precision to double conversion (bsc#943216).
- CVE-2015-8158: Fixed potential infinite loop in ntpq (bsc#962966).
- CVE-2015-8138: Zero Origin Timestamp Bypass (bsc#963002).
- CVE-2015-7979: Off-path Denial of Service (DoS) attack on authenticated broadcast mode (bsc#962784).
- CVE-2015-7978: Stack exhaustion in recursive traversal of restriction list (bsc#963000).
- CVE-2015-7977: reslist NULL pointer dereference (bsc#962970).
- CVE-2015-7976: ntpq saveconfig command allows dangerous characters in filenames (bsc#962802).
- CVE-2015-7975: nextvar() missing length check (bsc#962988).
- CVE-2015-7974: Skeleton Key: Missing key check allows impersonation between authenticated peers (bsc#962960).
- CVE-2015-7973: Replay attack on authenticated broadcast mode (bsc#962995).
- CVE-2015-8140: ntpq vulnerable to replay attacks (bsc#962994).
- CVE-2015-8139: Origin Leak: ntpq and ntpdc, disclose origin (bsc#962997).
- CVE-2015-5300: MITM attacker could have forced ntpd to make a step larger than the panic threshold (bsc#951629).
- CVE-2015-7871: NAK to the Future: Symmetric association authentication bypass via crypto-NAK (bsc#951608).
- CVE-2015-7855: decodenetnum() will ASSERT botch instead of returning FAIL on some bogus values (bsc#951608).
- CVE-2015-7854: Password Length Memory Corruption Vulnerability (bsc#951608).
- CVE-2015-7853: Invalid length data provided by a custom refclock driver could cause a buffer overflow (bsc#951608).
- CVE-2015-7852: ntpq atoascii() Memory Corruption Vulnerability (bsc#951608).
- CVE-2015-7851: saveconfig Directory Traversal Vulnerability (bsc#951608).
- CVE-2015-7850: remote config logfile-keyfile (bsc#951608).
- CVE-2015-7849: trusted key use-after-free (bsc#951608).
- CVE-2015-7848: mode 7 loop counter underrun (bsc#951608).
- CVE-2015-7701: Slow memory leak in CRYPTO_ASSOC (bsc#951608).
- CVE-2015-7703: configuration directives 'pidfile' and 'driftfile' should only be allowed locally (bsc#951608).
- CVE-2015-7704, CVE-2015-7705: Clients that receive a KoD should validate the origin timestamp field (bsc#951608).
- CVE-2015-7691, CVE-2015-7692, CVE-2015-7702: Incomplete ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ntp' package(s) on SUSE Linux Enterprise Server 11-SP2, SUSE Linux Enterprise Server 11-SP3.");

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

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.8p6~41.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-doc", rpm:"ntp-doc~4.2.8p6~41.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yast2-ntp-client", rpm:"yast2-ntp-client~2.17.14.1~1.12.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.8p6~41.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-doc", rpm:"ntp-doc~4.2.8p6~41.1", rls:"SLES11.0SP3"))) {
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
