# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.1146.1");
  script_cve_id("CVE-2015-7576", "CVE-2015-7577", "CVE-2015-7578", "CVE-2015-7579", "CVE-2015-7580", "CVE-2015-7581", "CVE-2016-0751", "CVE-2016-0752", "CVE-2016-0753", "CVE-2016-2098");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:07 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:56:09 +0000 (Tue, 16 Jul 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:1146-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:1146-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20161146-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'portus' package(s) announced via the SUSE-SU-2016:1146-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Portus was updated to version 2.0.3, which brings several fixes and enhancements:
- Fixed crono job when a repository could not be found.
- Fixed compatibility issues with Docker 1.10 and Distribution 2.3.
- Handle multiple scopes in token requests.
- Add optional fields to token response.
- Fixed notification events for Distribution v2.3.
- Paginate through the catalog properly.
- Do not remove all the repositories if fetching one fails.
- Fixed SMTP setup.
- Don't let crono overflow the 'log' column on the DB.
- Show the actual LDAP error on invalid login.
- Fixed the location of crono logs.
- Always use relative paths.
- Set RUBYLIB when using portusctl.
- Don't count hidden teams on the admin panel.
- Warn developers on unsupported docker-compose versions.
- Directly invalidate LDAP logins without name and password.
- Don't show the 'I forgot my password' link on LDAP.
The following Rubygems bundled within Portus have been updated to fix security issues:
- CVE-2016-2098: rubygem-actionpack (bsc#969943).
- CVE-2015-7578: rails-html-sanitizer (bsc#963326).
- CVE-2015-7579: rails-html-sanitizer (bsc#963327).
- CVE-2015-7580: rails-html-sanitizer (bsc#963328).
- CVE-2015-7576: rubygem-actionpack, rubygem-activesupport (bsc#963563).
- CVE-2015-7577: rubygem-activerecord (bsc#963604).
- CVE-2016-0751: rugygem-actionpack (bsc#963627).
- CVE-2016-0752: rubygem-actionpack, rubygem-actionview (bsc#963608).
- CVE-2016-0753: rubygem-activemodel, rubygem-activesupport,
 rubygem-activerecord (bsc#963617).
- CVE-2015-7581: rubygem-actionpack (bsc#963625).");

  script_tag(name:"affected", value:"'portus' package(s) on SUSE Linux Enterprise Module for Containers 12.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isrpmvuln(pkg:"portus", rpm:"portus~2.0.3~2.4", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"portus-debuginfo", rpm:"portus-debuginfo~2.0.3~2.4", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"portus-debugsource", rpm:"portus-debugsource~2.0.3~2.4", rls:"SLES12.0"))) {
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
