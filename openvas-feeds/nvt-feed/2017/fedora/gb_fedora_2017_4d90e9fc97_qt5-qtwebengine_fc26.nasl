# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.873859");
  script_version("2023-06-29T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-29 05:05:23 +0000 (Thu, 29 Jun 2023)");
  script_tag(name:"creation_date", value:"2017-12-05 07:55:25 +0100 (Tue, 05 Dec 2017)");
  script_cve_id("CVE-2017-5124", "CVE-2017-5126", "CVE-2017-5127", "CVE-2017-5128",
                "CVE-2017-5129", "CVE-2017-5132", "CVE-2017-5133", "CVE-2017-15386",
                "CVE-2017-15387", "CVE-2017-15388", "CVE-2017-15390", "CVE-2017-15392",
                "CVE-2017-15394", "CVE-2017-15396", "CVE-2017-15398");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-07 18:32:00 +0000 (Wed, 07 Nov 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for qt5-qtwebengine FEDORA-2017-4d90e9fc97");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'qt5-qtwebengine'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"qt5-qtwebengine on Fedora 26");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"FEDORA", value:"2017-4d90e9fc97");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/GXFTJOIBN72LGHKDWBWDGQS2CEFLOU5C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC26");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC26")
{

  if ((res = isrpmvuln(pkg:"qt5-qtwebengine", rpm:"qt5-qtwebengine~5.9.3~1.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
