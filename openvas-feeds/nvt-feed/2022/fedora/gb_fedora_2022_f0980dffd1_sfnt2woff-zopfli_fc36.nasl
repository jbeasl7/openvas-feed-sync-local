# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.822978");
  script_version("2025-04-24T05:40:01+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-24 05:40:01 +0000 (Thu, 24 Apr 2025)");
  script_tag(name:"creation_date", value:"2022-12-09 02:12:12 +0000 (Fri, 09 Dec 2022)");
  script_name("Fedora: Security Advisory for sfnt2woff-zopfli (FEDORA-2022-f0980dffd1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC36");

  script_xref(name:"Advisory-ID", value:"FEDORA-2022-f0980dffd1");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/FV6CQSC5UWR5DALQ64K6A2K7F6H4DRSD");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sfnt2woff-zopfli'
  package(s) announced via the FEDORA-2022-f0980dffd1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This is a modified version of the sfnt2woff utility that uses Zopfli as a
compression algorithm instead of zlib. This results in compression gains of
on average  5-8% compared to regular WOFF files. Zopfli generates compressed
output that is compatible with regular zlib compression so the resulting WOFF
files can be used everywhere.

A corresponding version of the woff2sfnt utility is also provided.");

  script_tag(name:"affected", value:"'sfnt2woff-zopfli' package(s) on Fedora 36.");

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

  if(!isnull(res = isrpmvuln(pkg:"sfnt2woff-zopfli", rpm:"sfnt2woff-zopfli~1.3.1~3.fc36", rls:"FC36"))) {
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
