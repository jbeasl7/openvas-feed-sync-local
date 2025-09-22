# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.1961.1");
  script_cve_id("CVE-2016-1238", "CVE-2017-15705", "CVE-2018-11780", "CVE-2018-11781");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-04 15:23:33 +0000 (Tue, 04 Dec 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:1961-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:1961-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20191961-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108745");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108748");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108750");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-July/005748.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'spamassassin' package(s) announced via the SUSE-SU-2019:1961-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for spamassassin to version 3.4.2 fixes the following issues:

Security issues fixed:

- CVE-2017-15705: Fixed denial of service via unclosed tags in crafted emails (bsc#1108745).
- CVE-2018-11781: Fixed a code injection in the meta rule syntax by local users (bsc#1108748).
- CVE-2018-11780: Fixed a potential remote code execution vulnerability in PDFInfo plugin (bsc#1108750).

Non-security issues fixed:

- Added four new plugins (disabled by default): HashBL, ResourceLimits, FromNameSpoof, Phishing
- sa-update script: optional support for SHA-256 / SHA-512 been added for better validation of rules
- GeoIP2 support has been added to RelayCountry and URILocalBL plugins
- Several new or enhanced configuration options");

  script_tag(name:"affected", value:"'spamassassin' package(s) on SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP4.");

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

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"perl-Mail-SpamAssassin", rpm:"perl-Mail-SpamAssassin~3.4.2~44.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spamassassin", rpm:"spamassassin~3.4.2~44.3.1", rls:"SLES12.0SP4"))) {
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
