# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.822170");
  script_version("2025-04-24T05:40:01+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-24 05:40:01 +0000 (Thu, 24 Apr 2025)");
  script_tag(name:"creation_date", value:"2022-07-31 01:15:29 +0000 (Sun, 31 Jul 2022)");
  script_name("Fedora: Security Advisory for golang-github-cloudflare (FEDORA-2022-5ef0bd9a27)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC36");

  script_xref(name:"Advisory-ID", value:"FEDORA-2022-5ef0bd9a27");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LF62X33BA3BAZKKWJXL4TQFQ23WC567S");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-github-cloudflare'
  package(s) announced via the FEDORA-2022-5ef0bd9a27 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A Go library for interacting with Cloudflare&#39, s API v4. This library allows you
to:

  - Manage and automate changes to your DNS records within Cloudflare

  - Manage and automate changes to your zones (domains) on Cloudflare, including
   adding new zones to your account

  - List and modify the status of WAF (Web Application Firewall) rules for your
   zones

  - Fetch Cloudflare&#39, s IP ranges for automating your firewall whitelisting

A command-line client, flarectl, is also available as part of this project.");

  script_tag(name:"affected", value:"'golang-github-cloudflare' package(s) on Fedora 36.");

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

  if(!isnull(res = isrpmvuln(pkg:"golang-github-cloudflare", rpm:"golang-github-cloudflare~0.21.0~4.fc36", rls:"FC36"))) {
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
