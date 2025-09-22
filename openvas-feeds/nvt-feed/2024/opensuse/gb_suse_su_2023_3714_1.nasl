# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833312");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2022-23517", "CVE-2022-23518", "CVE-2022-23519", "CVE-2022-23520");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-16 19:13:24 +0000 (Fri, 16 Dec 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 07:50:24 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for rubygem (SUSE-SU-2023:3714-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3714-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/V6OPT76VYMAHMC2QYM7QQ3EXEZEISEAL");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rubygem'
  package(s) announced via the SUSE-SU-2023:3714-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for rubygem-rails-html-sanitizer fixes the following issues:

  * CVE-2022-23517: Fixed inefficient regular expression that is susceptible to
      excessive backtracking when attempting to sanitize certain SVG attributes.
      (bsc#1206433)

  * CVE-2022-23518: Fixed XSS via data URIs when used in combination with
      Loofah. (bsc#1206434)

  * CVE-2022-23519: Fixed XSS vulnerability with certain configurations of
      Rails::Html::Sanitizer. (bsc#1206435)

  * CVE-2022-23520: Fixed XSS vulnerability with certain configurations of
      Rails::Html::Sanitizer. (bsc#1206436)

  ##");

  script_tag(name:"affected", value:"'rubygem' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-rubygem-rails-html-sanitizer-doc", rpm:"ruby2.5-rubygem-rails-html-sanitizer-doc~1.0.4~150000.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-rubygem-rails-html-sanitizer-testsuite", rpm:"ruby2.5-rubygem-rails-html-sanitizer-testsuite~1.0.4~150000.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-rubygem-rails-html-sanitizer", rpm:"ruby2.5-rubygem-rails-html-sanitizer~1.0.4~150000.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-rubygem-rails-html-sanitizer-doc", rpm:"ruby2.5-rubygem-rails-html-sanitizer-doc~1.0.4~150000.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-rubygem-rails-html-sanitizer-testsuite", rpm:"ruby2.5-rubygem-rails-html-sanitizer-testsuite~1.0.4~150000.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-rubygem-rails-html-sanitizer", rpm:"ruby2.5-rubygem-rails-html-sanitizer~1.0.4~150000.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-rubygem-rails-html-sanitizer-doc", rpm:"ruby2.5-rubygem-rails-html-sanitizer-doc~1.0.4~150000.4.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-rubygem-rails-html-sanitizer-testsuite", rpm:"ruby2.5-rubygem-rails-html-sanitizer-testsuite~1.0.4~150000.4.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-rubygem-rails-html-sanitizer", rpm:"ruby2.5-rubygem-rails-html-sanitizer~1.0.4~150000.4.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-rubygem-rails-html-sanitizer-doc", rpm:"ruby2.5-rubygem-rails-html-sanitizer-doc~1.0.4~150000.4.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-rubygem-rails-html-sanitizer-testsuite", rpm:"ruby2.5-rubygem-rails-html-sanitizer-testsuite~1.0.4~150000.4.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-rubygem-rails-html-sanitizer", rpm:"ruby2.5-rubygem-rails-html-sanitizer~1.0.4~150000.4.6.1", rls:"openSUSELeap15.5"))) {
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