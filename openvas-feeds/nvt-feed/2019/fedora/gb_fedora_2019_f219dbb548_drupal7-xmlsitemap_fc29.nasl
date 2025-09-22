# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.876452");
  script_version("2025-04-24T05:40:00+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-24 05:40:00 +0000 (Thu, 24 Apr 2025)");
  script_tag(name:"creation_date", value:"2019-06-05 02:18:06 +0000 (Wed, 05 Jun 2019)");
  script_name("Fedora Update for drupal7-xmlsitemap FEDORA-2019-f219dbb548");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC29");

  script_xref(name:"FEDORA", value:"2019-f219dbb548");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/RXENMLAMSYOIGXOOM7MIJVWQNLPWKI55");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'drupal7-xmlsitemap'
  package(s) announced via the FEDORA-2019-f219dbb548 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The XML sitemap module creates a sitemap.
This helps search engines to more intelligently crawl a
website and keep their results up to date. The sitemap created by the module
can be automatically submitted to Ask, Google, Bing (formerly Windows Live
Search), and Yahoo! search engines. The module also comes with several
submodules that can add sitemap links for content, menu items, taxonomy
terms, and user profiles.

Please read the included README.txt [2], the handbook documentation [3],
and the current list of known issues [4]for more information before using
the module.

This package provides the following Drupal modules:

  * xmlsitemap

  * xmlsitemap_custom

  * xmlsitemap_engines

  * xmlsitemap_i18n

  * xmlsitemap_menu

  * xmlsitemap_node

  * xmlsitemap_taxonomy

  * xmlsitemap_user");

  script_tag(name:"affected", value:"'drupal7-xmlsitemap' package(s) on Fedora 29.");

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

if(release == "FC29") {

  if(!isnull(res = isrpmvuln(pkg:"drupal7-xmlsitemap", rpm:"drupal7-xmlsitemap~2.6~1.fc29", rls:"FC29"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
