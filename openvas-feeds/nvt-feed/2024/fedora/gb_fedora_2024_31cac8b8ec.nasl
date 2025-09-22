# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886800");
  script_cve_id("CVE-2023-28755", "CVE-2023-36617", "CVE-2024-27280", "CVE-2024-27281", "CVE-2024-27282");
  script_tag(name:"creation_date", value:"2024-05-27 10:48:01 +0000 (Mon, 27 May 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-06 18:34:41 +0000 (Thu, 06 Jul 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2024-31cac8b8ec)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-31cac8b8ec");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-31cac8b8ec");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2218614");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2221559");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270544");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270749");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270750");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276810");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276813");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2277051");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2277060");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby' package(s) announced via the FEDORA-2024-31cac8b8ec advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Upgrade to Ruby 3.2.4.");

  script_tag(name:"affected", value:"'ruby' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"ruby", rpm:"ruby~3.2.4~182.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-bundled-gems", rpm:"ruby-bundled-gems~3.2.4~182.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-bundled-gems-debuginfo", rpm:"ruby-bundled-gems-debuginfo~3.2.4~182.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-debuginfo", rpm:"ruby-debuginfo~3.2.4~182.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-debugsource", rpm:"ruby-debugsource~3.2.4~182.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-default-gems", rpm:"ruby-default-gems~3.2.4~182.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-devel", rpm:"ruby-devel~3.2.4~182.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-doc", rpm:"ruby-doc~3.2.4~182.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-libs", rpm:"ruby-libs~3.2.4~182.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-libs-debuginfo", rpm:"ruby-libs-debuginfo~3.2.4~182.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-bigdecimal", rpm:"rubygem-bigdecimal~3.1.3~182.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-bigdecimal-debuginfo", rpm:"rubygem-bigdecimal-debuginfo~3.1.3~182.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-bundler", rpm:"rubygem-bundler~2.4.19~182.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-io-console", rpm:"rubygem-io-console~0.6.0~182.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-io-console-debuginfo", rpm:"rubygem-io-console-debuginfo~0.6.0~182.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-irb", rpm:"rubygem-irb~1.6.2~182.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-json", rpm:"rubygem-json~2.6.3~182.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-json-debuginfo", rpm:"rubygem-json-debuginfo~2.6.3~182.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-minitest", rpm:"rubygem-minitest~5.16.3~182.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-power_assert", rpm:"rubygem-power_assert~2.0.3~182.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-psych", rpm:"rubygem-psych~5.0.1~182.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-psych-debuginfo", rpm:"rubygem-psych-debuginfo~5.0.1~182.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-rake", rpm:"rubygem-rake~13.0.6~182.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-rbs", rpm:"rubygem-rbs~2.8.2~182.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-rbs-debuginfo", rpm:"rubygem-rbs-debuginfo~2.8.2~182.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-rdoc", rpm:"rubygem-rdoc~6.5.1.1~182.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-rexml", rpm:"rubygem-rexml~3.2.5~182.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-rss", rpm:"rubygem-rss~0.2.9~182.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-test-unit", rpm:"rubygem-test-unit~3.5.7~182.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-typeprof", rpm:"rubygem-typeprof~0.21.3~182.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygems", rpm:"rubygems~3.4.19~182.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygems-devel", rpm:"rubygems-devel~3.4.19~182.fc39", rls:"FC39"))) {
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
