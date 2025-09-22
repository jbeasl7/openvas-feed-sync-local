# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.2058.1");
  script_cve_id("CVE-2015-7691", "CVE-2015-7692", "CVE-2015-7701", "CVE-2015-7702", "CVE-2015-7703", "CVE-2015-7704", "CVE-2015-7705", "CVE-2015-7848", "CVE-2015-7849", "CVE-2015-7850", "CVE-2015-7851", "CVE-2015-7852", "CVE-2015-7853", "CVE-2015-7854", "CVE-2015-7855", "CVE-2015-7871");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:10 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-15 14:19:55 +0000 (Tue, 15 Aug 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:2058-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:2058-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20152058-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/905885");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/910063");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/936327");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/942441");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/942587");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/944300");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/951608");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-November/001688.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp' package(s) announced via the SUSE-SU-2015:2058-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This ntp update provides the following security and non security fixes:

- Update to 4.2.8p4 to fix several security issues (bsc#951608):
 * CVE-2015-7871: NAK to the Future: Symmetric association
 authentication bypass via crypto-NAK
 * CVE-2015-7855: decodenetnum() will ASSERT botch instead of
 returning FAIL on some bogus values
 * CVE-2015-7854: Password Length Memory Corruption Vulnerability
 * CVE-2015-7853: Invalid length data provided by a custom
 refclock driver could cause a buffer overflow
 * CVE-2015-7852 ntpq atoascii() Memory Corruption Vulnerability
 * CVE-2015-7851 saveconfig Directory Traversal Vulnerability
 * CVE-2015-7850 remote config logfile-keyfile
 * CVE-2015-7849 trusted key use-after-free
 * CVE-2015-7848 mode 7 loop counter underrun
 * CVE-2015-7701 Slow memory leak in CRYPTO_ASSOC
 * CVE-2015-7703 configuration directives 'pidfile' and
 'driftfile' should only be allowed locally
 * CVE-2015-7704, CVE-2015-7705 Clients that receive a KoD should
 validate the origin timestamp field
 * CVE-2015-7691, CVE-2015-7692, CVE-2015-7702 Incomplete autokey
 data packet length checks
- Use ntpq instead of deprecated ntpdc in start-ntpd (bnc#936327).
- Add a controlkey to ntp.conf to make the above work.
- Improve runtime configuration:
 * Read keytype from ntp.conf
 * Don't write ntp keys to syslog.
- Don't let 'keysdir' lines in ntp.conf trigger the 'keys' parser.
- Fix the comment regarding addserver in ntp.conf (bnc#910063).
- Remove ntp.1.gz, it wasn't installed anymore.
- Remove ntp-4.2.7-rh-manpages.tar.gz and only keep ntptime.8.gz.
 The rest is partially irrelevant, partially redundant and
 potentially outdated (bsc#942587).
- Remove 'kod' from the restrict line in ntp.conf (bsc#944300).
- Use SHA1 instead of MD5 for symmetric keys (bsc#905885).
- Require perl-Socket6 (bsc#942441).
- Fix incomplete backporting of 'rcntp ntptimemset'.");

  script_tag(name:"affected", value:"'ntp' package(s) on SUSE Linux Enterprise Desktop 11-SP4, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.8p4~5.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-doc", rpm:"ntp-doc~4.2.8p4~5.1", rls:"SLES11.0SP4"))) {
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
