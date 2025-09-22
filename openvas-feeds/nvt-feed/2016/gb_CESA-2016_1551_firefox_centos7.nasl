# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882534");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-08-08 15:11:53 +0530 (Mon, 08 Aug 2016)");
  script_cve_id("CVE-2016-2830", "CVE-2016-2836", "CVE-2016-2837", "CVE-2016-2838",
                "CVE-2016-5252", "CVE-2016-5254", "CVE-2016-5258", "CVE-2016-5259",
                "CVE-2016-5262", "CVE-2016-5263", "CVE-2016-5264", "CVE-2016-5265");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for firefox CESA-2016:1551 centos7");
  script_tag(name:"summary", value:"Check the version of firefox");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Mozilla Firefox is an open source web browser.

This update upgrades Firefox to version 45.3.0 ESR.

Security Fix(es):

  * Multiple flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user running
Firefox. (CVE-2016-2836, CVE-2016-5258, CVE-2016-5259, CVE-2016-5252,
CVE-2016-5263, CVE-2016-2830, CVE-2016-2838, CVE-2016-5254, CVE-2016-5262,
CVE-2016-5264, CVE-2016-5265, CVE-2016-2837)

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Looben Yang, Carsten Book, Christian Holler, Gary
Kwong, Jesse Ruderman, Andrew McCreight, Phil Ringnalda, Philipp, Toni
Huttunen, Georg Koppen, Abhishek Arya, Atte Kettunen, Nils, Nikita Arykov,
and Abdulrahman Alqabandi as the original reporters.");
  script_tag(name:"affected", value:"firefox on CentOS 7");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2016:1551");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2016-August/022024.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~45.3.0~1.el7.centos", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
