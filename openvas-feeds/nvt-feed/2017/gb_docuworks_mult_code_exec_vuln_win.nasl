# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:fujixerox:docuworks";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811733");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2017-10848", "CVE-2017-10849");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-06 18:43:00 +0000 (Wed, 06 Sep 2017)");
  script_tag(name:"creation_date", value:"2017-09-08 15:03:17 +0530 (Fri, 08 Sep 2017)");
  script_name("DocuWorks Multiple Code Execution Vulnerabilities - Windows");

  script_tag(name:"summary", value:"DocuWorks is prone to multiple code execution vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to an issue with the
  DLL search path, which may lead to insecurely loading Dynamic Link Libraries.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain escalated privileges and run arbitrary code on the affected
  system.");

  script_tag(name:"affected", value:"DocuWorks versions 8.0.7 and earlier.");

  script_tag(name:"solution", value:"Upgrade to DocuWorks versions 8.0.8 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://jvn.jp/en/jp/JVN09769017/index.html");
  script_xref(name:"URL", value:"http://www.fujixerox.co.jp/company/news/notice/2017/0831_rectification_work_2.html");
  script_xref(name:"URL", value:"http://www.fujixerox.co.jp");

  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_docuworks_detect_win.nasl");
  script_mandatory_keys("DocuWorks/Win/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!version = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:version, test_version:"8.0.8"))
{
  report = report_fixed_ver(installed_version:version, fixed_version:"8.0.8");
  security_message(data:report);
  exit(0);
}
exit(0);
