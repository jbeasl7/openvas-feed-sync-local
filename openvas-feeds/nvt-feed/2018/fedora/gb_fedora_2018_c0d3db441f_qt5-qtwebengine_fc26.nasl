# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.874155");
  script_version("2023-06-28T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-28 05:05:22 +0000 (Wed, 28 Jun 2023)");
  script_tag(name:"creation_date", value:"2018-02-28 08:38:39 +0100 (Wed, 28 Feb 2018)");
  script_cve_id("CVE-2017-15407", "CVE-2017-15409", "CVE-2017-15410", "CVE-2017-15411",
                "CVE-2017-15415", "CVE-2017-15416", "CVE-2017-15418", "CVE-2017-15419",
                "CVE-2017-15422", "CVE-2017-15423", "CVE-2017-15424", "CVE-2017-15425",
                "CVE-2017-15426", "CVE-2018-6031", "CVE-2018-6033", "CVE-2018-6034",
                "CVE-2018-6036", "CVE-2018-6037", "CVE-2018-6038", "CVE-2018-6040",
                "CVE-2018-6041", "CVE-2018-6042", "CVE-2018-6047", "CVE-2018-6048",
                "CVE-2018-6050", "CVE-2018-6051", "CVE-2018-6052", "CVE-2018-6053",
                "CVE-2018-6054");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-20 18:13:00 +0000 (Tue, 20 Nov 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for qt5-qtwebengine FEDORA-2018-c0d3db441f");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'qt5-qtwebengine'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"qt5-qtwebengine on Fedora 26");
  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"FEDORA", value:"2018-c0d3db441f");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/TMXSXUQWLJLP4VC53CAE7HL3ZUFJZY6I");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"qt5-qtwebengine", rpm:"qt5-qtwebengine~5.10.1~1.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
