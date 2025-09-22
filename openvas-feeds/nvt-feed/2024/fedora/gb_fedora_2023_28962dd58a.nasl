# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2023.289621001005897");
  script_tag(name:"creation_date", value:"2024-09-10 12:16:00 +0000 (Tue, 10 Sep 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2023-28962dd58a)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-28962dd58a");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-28962dd58a");
  script_xref(name:"URL", value:"https://rubyonrails.org/2023/8/22/Rails-Versions-7-0-7-2-6-1-7-6-have-been-released");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rubygem-actioncable, rubygem-actionmailbox, rubygem-actionmailer, rubygem-actionpack, rubygem-actiontext, rubygem-actionview, rubygem-activejob, rubygem-activemodel, rubygem-activerecord, rubygem-activestorage, rubygem-activesupport, rubygem-rails, rubygem-railties' package(s) announced via the FEDORA-2023-28962dd58a advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ruby on Rails security upgrade: [link moved to references] - incorrect file permissions on encrypted files. Exploit not known.");

  script_tag(name:"affected", value:"'rubygem-actioncable, rubygem-actionmailbox, rubygem-actionmailer, rubygem-actionpack, rubygem-actiontext, rubygem-actionview, rubygem-activejob, rubygem-activemodel, rubygem-activerecord, rubygem-activestorage, rubygem-activesupport, rubygem-rails, rubygem-railties' package(s) on Fedora 40.");

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

if(release == "FC40") {

  if(!isnull(res = isrpmvuln(pkg:"rubygem-actioncable", rpm:"rubygem-actioncable~7.0.7.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-actioncable-doc", rpm:"rubygem-actioncable-doc~7.0.7.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-actionmailbox", rpm:"rubygem-actionmailbox~7.0.7.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-actionmailbox-doc", rpm:"rubygem-actionmailbox-doc~7.0.7.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-actionmailer", rpm:"rubygem-actionmailer~7.0.7.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-actionmailer-doc", rpm:"rubygem-actionmailer-doc~7.0.7.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-actionpack", rpm:"rubygem-actionpack~7.0.7.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-actionpack-doc", rpm:"rubygem-actionpack-doc~7.0.7.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-actiontext", rpm:"rubygem-actiontext~7.0.7.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-actiontext-doc", rpm:"rubygem-actiontext-doc~7.0.7.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-actionview", rpm:"rubygem-actionview~7.0.7.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-actionview-doc", rpm:"rubygem-actionview-doc~7.0.7.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-activejob", rpm:"rubygem-activejob~7.0.7.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-activejob-doc", rpm:"rubygem-activejob-doc~7.0.7.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-activemodel", rpm:"rubygem-activemodel~7.0.7.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-activemodel-doc", rpm:"rubygem-activemodel-doc~7.0.7.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-activerecord", rpm:"rubygem-activerecord~7.0.7.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-activerecord-doc", rpm:"rubygem-activerecord-doc~7.0.7.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-activestorage", rpm:"rubygem-activestorage~7.0.7.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-activestorage-doc", rpm:"rubygem-activestorage-doc~7.0.7.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-activesupport", rpm:"rubygem-activesupport~7.0.7.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-activesupport-doc", rpm:"rubygem-activesupport-doc~7.0.7.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-rails", rpm:"rubygem-rails~7.0.7.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-rails-doc", rpm:"rubygem-rails-doc~7.0.7.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-railties", rpm:"rubygem-railties~7.0.7.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-railties-doc", rpm:"rubygem-railties-doc~7.0.7.2~1.fc40", rls:"FC40"))) {
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
