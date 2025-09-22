# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.fedoraproject.org/pipermail/package-announce/2013-January/097635.html");
  script_oid("1.3.6.1.4.1.25623.1.0.865262");
  script_version("2023-06-22T10:34:15+0000");
  script_tag(name:"last_modification", value:"2023-06-22 10:34:15 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"creation_date", value:"2013-01-31 09:24:39 +0530 (Thu, 31 Jan 2013)");
  script_cve_id("CVE-2012-1126", "CVE-2012-1127", "CVE-2012-1128", "CVE-2012-1130",
                "CVE-2012-1131", "CVE-2012-1132", "CVE-2012-1133", "CVE-2012-1134",
                "CVE-2012-1135", "CVE-2012-1136", "CVE-2012-1137", "CVE-2012-1138",
                "CVE-2012-1139", "CVE-2012-1140", "CVE-2012-1141", "CVE-2012-1142",
                "CVE-2012-1143", "CVE-2012-1144");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"FEDORA", value:"2013-1114");
  script_name("Fedora Update for mingw-freetype FEDORA-2013-1114");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'mingw-freetype'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC17");
  script_tag(name:"affected", value:"mingw-freetype on Fedora 17");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC17")
{

  if ((res = isrpmvuln(pkg:"mingw-freetype", rpm:"mingw-freetype~2.4.11~1.fc17", rls:"FC17")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
