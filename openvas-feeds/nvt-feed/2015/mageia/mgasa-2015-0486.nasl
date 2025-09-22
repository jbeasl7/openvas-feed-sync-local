# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131161");
  script_cve_id("CVE-2015-8622", "CVE-2015-8623", "CVE-2015-8624", "CVE-2015-8625", "CVE-2015-8626", "CVE-2015-8627", "CVE-2015-8628");
  script_tag(name:"creation_date", value:"2015-12-28 08:39:24 +0000 (Mon, 28 Dec 2015)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-27 14:06:01 +0000 (Mon, 27 Mar 2017)");

  script_name("Mageia: Security Advisory (MGASA-2015-0486)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0486");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0486.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/12/23/7");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17379");
  script_xref(name:"URL", value:"https://lists.wikimedia.org/pipermail/mediawiki-announce/2015-December/000186.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mediawiki' package(s) announced via the MGASA-2015-0486 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated mediawiki packages fix security vulnerabilities:

In MediaWiki before 1.23.12, an XSS vector exists when MediaWiki is
configured with a non-standard configuration, from wikitext when
$wgArticlePath='$1' (CVE-2015-8622).

In MediaWiki before 1.23.12, tokens were being compared as strings, which
could allow a timing attack (CVE-2015-8623, CVE-2015-8624).

In MediaWiki before 1.23.12, parameters passed to the curl library were not
sanitized, which could cause curl to upload files from the webserver to an
attacker when POST variable starts with '@' (CVE-2015-8625).

In MediaWiki before 1.23.12, the password reset token could be shorter than
the minimum required password length (CVE-2015-8626).

In MediaWiki before 1.23.12, blocking IP addresses with zero-padded octets
resulted in a failure to block the IP address (CVE-2015-8627).

In MediaWiki before 1.23.12, a combination of Special:MyPage redirects and
pagecounts allows an external site to know the wikipedia login of an user
(CVE-2015-8628).");

  script_tag(name:"affected", value:"'mediawiki' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"mediawiki", rpm:"mediawiki~1.23.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-mysql", rpm:"mediawiki-mysql~1.23.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-pgsql", rpm:"mediawiki-pgsql~1.23.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-sqlite", rpm:"mediawiki-sqlite~1.23.12~1.mga5", rls:"MAGEIA5"))) {
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
