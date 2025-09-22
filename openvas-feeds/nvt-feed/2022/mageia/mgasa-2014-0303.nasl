# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0303");
  script_cve_id("CVE-2014-0130", "CVE-2014-3483");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:57:52 +0000 (Tue, 16 Jul 2024)");

  script_name("Mageia: Security Advisory (MGASA-2014-0303)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0303");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0303.html");
  script_xref(name:"URL", value:"http://weblog.rubyonrails.org/2014/5/6/Rails_3_2_18_4_0_5_and_4_1_1_have_been_released/");
  script_xref(name:"URL", value:"http://weblog.rubyonrails.org/2014/6/26/Rails-4-1-2-and-4-0-6-has-been-released/");
  script_xref(name:"URL", value:"http://weblog.rubyonrails.org/2014/7/2/Rails_3_2_19_4_0_7_and_4_1_3_have_been_released/");
  script_xref(name:"URL", value:"http://weblog.rubyonrails.org/2014/7/2/Rails_4_0_8_and_4_1_4_have_been_released/");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13339");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13659");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby-actionmailer, ruby-actionpack, ruby-activemodel, ruby-activerecord, ruby-activesupport, ruby-rails, ruby-railties' package(s) announced via the MGASA-2014-0303 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated ruby-actionpack and ruby-activerecord packages fix security
vulnerabilities:

Directory traversal vulnerability in actionpack/lib/abstract_controller/base.rb
in the implicit-render implementation in Ruby on Rails before 4.0.5, when
certain route globbing configurations are enabled, allows remote attackers to
read arbitrary files via a crafted request (CVE-2014-0130).

PostgreSQL supports a number of unique data types which are not present in
other supported databases. A bug in the SQL quoting code in ActiveRecord in
Ruby on Rails before 4.0.7 can allow an attacker to inject arbitrary SQL using
carefully crafted values (CVE-2014-3483).

The associated Ruby on Rails packages have been updated to version 4.0.8, to
address these and other issues.");

  script_tag(name:"affected", value:"'ruby-actionmailer, ruby-actionpack, ruby-activemodel, ruby-activerecord, ruby-activesupport, ruby-rails, ruby-railties' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"ruby-actionmailer", rpm:"ruby-actionmailer~4.0.8~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-actionmailer-doc", rpm:"ruby-actionmailer-doc~4.0.8~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-actionpack", rpm:"ruby-actionpack~4.0.8~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-actionpack-doc", rpm:"ruby-actionpack-doc~4.0.8~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-activemodel", rpm:"ruby-activemodel~4.0.8~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-activemodel-doc", rpm:"ruby-activemodel-doc~4.0.8~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-activerecord", rpm:"ruby-activerecord~4.0.8~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-activerecord-doc", rpm:"ruby-activerecord-doc~4.0.8~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-activesupport", rpm:"ruby-activesupport~4.0.8~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-activesupport-doc", rpm:"ruby-activesupport-doc~4.0.8~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-rails", rpm:"ruby-rails~4.0.8~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-rails-doc", rpm:"ruby-rails-doc~4.0.8~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-railties", rpm:"ruby-railties~4.0.8~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-railties-doc", rpm:"ruby-railties-doc~4.0.8~1.mga4", rls:"MAGEIA4"))) {
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
