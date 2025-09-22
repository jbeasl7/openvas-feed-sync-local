# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886335");
  script_version("2024-04-18T05:05:33+0000");
  script_cve_id("CVE-2022-40896");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-04-18 05:05:33 +0000 (Thu, 18 Apr 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-26 21:04:56 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2024-03-28 02:11:16 +0000 (Thu, 28 Mar 2024)");
  script_name("Fedora: Security Advisory for python-pygments (FEDORA-2024-8eaf80107a)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-8eaf80107a");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/EZGMXALE3HSP4OXC7UUWIKX3OXKZDTY3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-pygments'
  package(s) announced via the FEDORA-2024-8eaf80107a advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Pygments is a generic syntax highlighter suitable for use in code hosting,
forums, wikis or other applications that need to prettify source code.

Highlights are:

  * a wide range of over 500 languages and other text formats is supported

  * special attention is paid to details that increase highlighting quality

  * support for new languages and formats are added easily,
   most languages use a simple regex-based lexing mechanism

  * a number of output formats is available, among them HTML, RTF, LaTeX
   and ANSI sequences

  * it is usable as a command-line tool and as a library");

  script_tag(name:"affected", value:"'python-pygments' package(s) on Fedora 38.");

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

if(release == "FC38") {

  if(!isnull(res = isrpmvuln(pkg:"python-pygments", rpm:"python-pygments~2.14.0~2.fc38", rls:"FC38"))) {
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