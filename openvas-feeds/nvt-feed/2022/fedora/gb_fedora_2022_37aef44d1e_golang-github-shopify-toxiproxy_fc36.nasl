# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.821982");
  script_version("2025-04-24T05:40:00+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-24 05:40:00 +0000 (Thu, 24 Apr 2025)");
  script_tag(name:"creation_date", value:"2022-07-31 01:15:29 +0000 (Sun, 31 Jul 2022)");
  script_name("Fedora: Security Advisory for golang-github-shopify-toxiproxy (FEDORA-2022-37aef44d1e)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC36");

  script_xref(name:"Advisory-ID", value:"FEDORA-2022-37aef44d1e");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/CYULELC3AWNGE7YRDSFXSQBAFSGAIEKR");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-github-shopify-toxiproxy'
  package(s) announced via the FEDORA-2022-37aef44d1e advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Toxiproxy is a framework for simulating network conditions. It&#39, s made
specifically to work in testing, CI and development environments, supporting
deterministic tampering with connections, but with support for randomized
chaos and customization. Toxiproxy is the tool you need to prove with tests
that your application doesn&#39, t have single points of failure.

Toxiproxy usage consists of two parts. A TCP proxy written in Go (what this
repository contains) and a client communicating with the proxy over HTTP. You
configure your application to make all test connections go through Toxiproxy
and can then manipulate their health via HTTP. See Usage below on how to set
up your project.");

  script_tag(name:"affected", value:"'golang-github-shopify-toxiproxy' package(s) on Fedora 36.");

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

  if(!isnull(res = isrpmvuln(pkg:"golang-github-shopify-toxiproxy", rpm:"golang-github-shopify-toxiproxy~2.1.4~11.fc36", rls:"FC36"))) {
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
