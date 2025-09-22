# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0191");
  script_cve_id("CVE-2014-0080", "CVE-2014-0081");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2014-0191)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0191");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0191.html");
  script_xref(name:"URL", value:"http://weblog.rubyonrails.org/2014/2/18/Rails_3_2_17_4_0_3_and_4_1_0_beta2_have_been_released/");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=12896");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2014-March/129715.html");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2014-March/129716.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby-actionmailer, ruby-actionpack, ruby-activemodel, ruby-activerecord, ruby-activesupport, ruby-rails, ruby-railties' package(s) announced via the MGASA-2014-0191 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated ruby-activerecord and ruby-actionpack packages fix security
vulnerabilities:

There is a data injection vulnerability in Active Record. Specially crafted
strings can be used to save data in PostgreSQL array columns that may not be
intended (CVE-2014-0080).

There is an XSS vulnerability in the number_to_currency, number_to_percentage
and number_to_human helpers in Ruby on Rails (CVE-2014-0081).

The associated packages have been updated to version 4.0.3 to fix these
issues.");

  script_tag(name:"affected", value:"'ruby-actionmailer, ruby-actionpack, ruby-activemodel, ruby-activerecord, ruby-activesupport, ruby-rails, ruby-railties' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"ruby-actionmailer", rpm:"ruby-actionmailer~4.0.3~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-actionmailer-doc", rpm:"ruby-actionmailer-doc~4.0.3~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-actionpack", rpm:"ruby-actionpack~4.0.3~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-actionpack-doc", rpm:"ruby-actionpack-doc~4.0.3~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-activemodel", rpm:"ruby-activemodel~4.0.3~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-activemodel-doc", rpm:"ruby-activemodel-doc~4.0.3~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-activerecord", rpm:"ruby-activerecord~4.0.3~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-activerecord-doc", rpm:"ruby-activerecord-doc~4.0.3~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-activesupport", rpm:"ruby-activesupport~4.0.3~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-activesupport-doc", rpm:"ruby-activesupport-doc~4.0.3~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-rails", rpm:"ruby-rails~4.0.3~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-rails-doc", rpm:"ruby-rails-doc~4.0.3~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-railties", rpm:"ruby-railties~4.0.3~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-railties-doc", rpm:"ruby-railties-doc~4.0.3~1.mga4", rls:"MAGEIA4"))) {
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
