# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.822607");
  script_version("2025-04-24T05:40:01+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-24 05:40:01 +0000 (Thu, 24 Apr 2025)");
  script_tag(name:"creation_date", value:"2022-10-08 01:13:55 +0000 (Sat, 08 Oct 2022)");
  script_name("Fedora: Security Advisory for php-twig3 (FEDORA-2022-b7dcd1cde4)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC36");

  script_xref(name:"Advisory-ID", value:"FEDORA-2022-b7dcd1cde4");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/3CBXQ7IL7YHKAY7XFCJAFZS4RVUM7QQR");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php-twig3'
  package(s) announced via the FEDORA-2022-b7dcd1cde4 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The flexible, fast, and secure template engine for PHP.

  * Fast: Twig compiles templates down to plain optimized PHP code. The
  overhead compared to regular PHP code was reduced to the very minimum.

  * Secure: Twig has a sandbox mode to evaluate untrusted template code. This
  allows Twig to be used as a template language for applications where users
  may modify the template design.

  * Flexible: Twig is powered by a flexible lexer and parser. This allows the
  developer to define its own custom tags and filters, and create its own
  DSL.

Autoloader: /usr/share/php/Twig3/autoload.php");

  script_tag(name:"affected", value:"'php-twig3' package(s) on Fedora 36.");

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

  if(!isnull(res = isrpmvuln(pkg:"php-twig3", rpm:"php-twig3~3.4.3~1.fc36", rls:"FC36"))) {
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
