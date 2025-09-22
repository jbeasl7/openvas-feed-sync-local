# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.1912.1");
  script_cve_id("CVE-2015-1798", "CVE-2015-1799", "CVE-2015-5194", "CVE-2015-5300", "CVE-2015-7691", "CVE-2015-7692", "CVE-2015-7701", "CVE-2015-7702", "CVE-2015-7703", "CVE-2015-7704", "CVE-2015-7705", "CVE-2015-7848", "CVE-2015-7849", "CVE-2015-7850", "CVE-2015-7851", "CVE-2015-7852", "CVE-2015-7853", "CVE-2015-7854", "CVE-2015-7855", "CVE-2015-7871", "CVE-2015-7973", "CVE-2015-7974", "CVE-2015-7975", "CVE-2015-7976", "CVE-2015-7977", "CVE-2015-7978", "CVE-2015-7979", "CVE-2015-8138", "CVE-2015-8158", "CVE-2016-1547", "CVE-2016-1548", "CVE-2016-1549", "CVE-2016-1550", "CVE-2016-1551", "CVE-2016-2516", "CVE-2016-2517", "CVE-2016-2518", "CVE-2016-2519", "CVE-2016-4953", "CVE-2016-4954", "CVE-2016-4955", "CVE-2016-4956", "CVE-2016-4957");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:05 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-15 14:19:55 +0000 (Tue, 15 Aug 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:1912-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:1912-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20161912-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp' package(s) announced via the SUSE-SU-2016:1912-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"NTP was updated to version 4.2.8p8 to fix several security issues and to ensure the continued maintainability of the package.
These security issues were fixed:
CVE-2016-4953: Bad authentication demobilized ephemeral associations (bsc#982065).
CVE-2016-4954: Processing spoofed server packets (bsc#982066).
CVE-2016-4955: Autokey association reset (bsc#982067).
CVE-2016-4956: Broadcast interleave (bsc#982068).
CVE-2016-4957: CRYPTO_NAK crash (bsc#982064).
CVE-2016-1547: Validate crypto-NAKs to prevent ACRYPTO-NAK DoS (bsc#977459).
CVE-2016-1548: Prevent the change of time of an ntpd client or denying service to an ntpd client by forcing it to change from basic client/server mode to interleaved symmetric mode (bsc#977461).
CVE-2016-1549: Sybil vulnerability: ephemeral association attack (bsc#977451).
CVE-2016-1550: Improve security against buffer comparison timing attacks (bsc#977464).
CVE-2016-1551: Refclock impersonation vulnerability (bsc#977450)y CVE-2016-2516: Duplicate IPs on unconfig directives could have caused an assertion botch in ntpd (bsc#977452).
CVE-2016-2517: Remote configuration trustedkey/ requestkey/controlkey values are not properly validated (bsc#977455).
CVE-2016-2518: Crafted addpeer with hmode > 7 causes array wraparound with MATCH_ASSOC (bsc#977457).
CVE-2016-2519: ctl_getitem() return value not always checked (bsc#977458).
CVE-2015-8158: Potential Infinite Loop in ntpq (bsc#962966).
CVE-2015-8138: Zero Origin Timestamp Bypass (bsc#963002).
CVE-2015-7979: Off-path Denial of Service (DoS) attack on authenticated broadcast mode (bsc#962784).
CVE-2015-7978: Stack exhaustion in recursive traversal of restriction list (bsc#963000).
CVE-2015-7977: reslist NULL pointer dereference (bsc#962970).
CVE-2015-7976: ntpq saveconfig command allowed dangerous characters in filenames (bsc#962802).
CVE-2015-7975: nextvar() missing length check (bsc#962988).
CVE-2015-7974: NTP did not verify peer associations of symmetric keys when authenticating packets, which might have allowed remote attackers to conduct impersonation attacks via an arbitrary trusted key, aka a 'skeleton' key (bsc#962960).
CVE-2015-7973: Replay attack on authenticated broadcast mode (bsc#962995).
CVE-2015-5300: MITM attacker can force ntpd to make a step larger than the panic threshold (bsc#951629).
CVE-2015-5194: Crash with crafted logconfig configuration command (bsc#943218).
CVE-2015-7871: NAK to the Future: Symmetric association authentication bypass via crypto-NAK (bsc#952611).
CVE-2015-7855: decodenetnum() will ASSERT botch instead of returning FAIL on some bogus values (bsc#952611).
CVE-2015-7854: Password Length Memory Corruption Vulnerability (bsc#952611).
CVE-2015-7853: Invalid length data provided by a custom refclock driver could cause a buffer overflow (bsc#952611).
CVE-2015-7852: ntpq atoascii() Memory Corruption Vulnerability (bsc#952611).
CVE-2015-7851: saveconfig Directory Traversal ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ntp' package(s) on SUSE Linux Enterprise Server 10-SP4.");

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

if(release == "SLES10.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.8p8~0.7.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-doc", rpm:"ntp-doc~4.2.8p8~0.7.1", rls:"SLES10.0SP4"))) {
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
