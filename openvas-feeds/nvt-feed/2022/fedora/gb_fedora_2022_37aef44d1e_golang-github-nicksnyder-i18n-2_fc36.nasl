# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.822181");
  script_version("2025-04-24T05:40:00+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-24 05:40:00 +0000 (Thu, 24 Apr 2025)");
  script_tag(name:"creation_date", value:"2022-07-31 01:15:29 +0000 (Sun, 31 Jul 2022)");
  script_name("Fedora: Security Advisory for golang-github-nicksnyder-i18n-2 (FEDORA-2022-37aef44d1e)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC36");

  script_xref(name:"Advisory-ID", value:"FEDORA-2022-37aef44d1e");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/5Q42MUF2R77DQYDWPRIV3JT45LHEJFGB");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-github-nicksnyder-i18n-2'
  package(s) announced via the FEDORA-2022-37aef44d1e advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"go-i18n is a Go package and a command that helps you translate Go programs into
multiple languages.

  - Supports pluralized strings for all 200+ languages in the Unicode Common
   Locale Data Repository (CLDR).

  - Code and tests are automatically generated from CLDR data.

  - Supports strings with named variables using text/template syntax.

  - Supports message files of any format (e.g. JSON, TOML, YAML, etc.).

  - Documented and tested!");

  script_tag(name:"affected", value:"'golang-github-nicksnyder-i18n-2' package(s) on Fedora 36.");

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

if(release == "FC36") {

  if(!isnull(res = isrpmvuln(pkg:"golang-github-nicksnyder-i18n-2", rpm:"golang-github-nicksnyder-i18n-2~2.1.2~6.fc36", rls:"FC36"))) {
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
