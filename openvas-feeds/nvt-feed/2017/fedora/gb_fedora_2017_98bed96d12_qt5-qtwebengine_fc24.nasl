# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.872901");
  script_version("2023-06-30T05:06:12+0000");
  script_tag(name:"last_modification", value:"2023-06-30 05:06:12 +0000 (Fri, 30 Jun 2023)");
  script_tag(name:"creation_date", value:"2017-07-24 05:44:15 +0200 (Mon, 24 Jul 2017)");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2016-5133", "CVE-2016-5147", "CVE-2016-5153", "CVE-2016-5155",
                "CVE-2016-5161", "CVE-2016-5166", "CVE-2016-5170", "CVE-2016-5171",
                "CVE-2016-5172", "CVE-2016-5181", "CVE-2016-5185", "CVE-2016-5186",
                "CVE-2016-5187", "CVE-2016-5188", "CVE-2016-5192", "CVE-2016-5198",
                "CVE-2016-5205", "CVE-2016-5207", "CVE-2016-5208", "CVE-2016-5214",
                "CVE-2016-5215", "CVE-2016-5221", "CVE-2016-5222", "CVE-2016-5224",
                "CVE-2016-5225", "CVE-2016-9650", "CVE-2016-9651", "CVE-2016-9652",
                "CVE-2017-5006", "CVE-2017-5007", "CVE-2017-5008", "CVE-2017-5009",
                "CVE-2017-5010", "CVE-2017-5012", "CVE-2017-5015", "CVE-2017-5016",
                "CVE-2017-5017", "CVE-2017-5019", "CVE-2017-5023", "CVE-2017-5024",
                "CVE-2017-5025", "CVE-2017-5026", "CVE-2017-5027", "CVE-2017-5029",
                "CVE-2017-5033", "CVE-2017-5037", "CVE-2017-5044", "CVE-2017-5046",
                "CVE-2017-5047", "CVE-2017-5048", "CVE-2017-5049", "CVE-2017-5050",
                "CVE-2017-5051", "CVE-2017-5059", "CVE-2017-5061", "CVE-2017-5062",
                "CVE-2017-5065", "CVE-2017-5067", "CVE-2017-5069", "CVE-2017-5070",
                "CVE-2017-5071", "CVE-2017-5075", "CVE-2017-5076", "CVE-2016-5078",
                "CVE-2017-5083", "CVE-2017-5089");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-07 21:15:00 +0000 (Fri, 07 Feb 2020)");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for qt5-qtwebengine FEDORA-2017-98bed96d12");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'qt5-qtwebengine'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"qt5-qtwebengine on Fedora 24");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"FEDORA", value:"2017-98bed96d12");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LV2U7SINGF3SBK7HVKSWFOYLQBUH6PUE");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC24");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC24")
{

  if ((res = isrpmvuln(pkg:"qt5-qtwebengine", rpm:"qt5-qtwebengine~5.6.3~0.1.20170712gitee719ad313e564.fc24", rls:"FC24")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
