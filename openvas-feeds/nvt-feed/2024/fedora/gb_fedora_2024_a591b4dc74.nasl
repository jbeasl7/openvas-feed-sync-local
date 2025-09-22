# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.887093");
  script_tag(name:"creation_date", value:"2024-06-07 06:35:53 +0000 (Fri, 07 Jun 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-a591b4dc74)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-a591b4dc74");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-a591b4dc74");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2281597");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2281598");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'roundcubemail' package(s) announced via the FEDORA-2024-a591b4dc74 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"**Release 1.6.7**

- Makefile: Use phpDocumentor v3.4 for the Framework docs (#9313)
- Fix bug where HTML entities in URLs were not decoded on HTML to plain text conversion (#9312)
- Fix bug in collapsing/expanding folders with some special characters in names (#9324)
- Fix PHP8 warnings (#9363, #9365, #9429)
- Fix missing field labels in CSV import, for some locales (#9393)
- Fix command injection via crafted im_convert_path/im_identify_path on Windows
- Fix cross-site scripting (XSS) vulnerability in handling list columns from user preferences
- Fix cross-site scripting (XSS) vulnerability in handling SVG animate attributes");

  script_tag(name:"affected", value:"'roundcubemail' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"roundcubemail", rpm:"roundcubemail~1.6.7~1.fc39", rls:"FC39"))) {
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
