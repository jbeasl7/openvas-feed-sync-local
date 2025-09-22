# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:hp:intelligent_management_center";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809283");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2012-5201", "CVE-2012-5202", "CVE-2012-5203", "CVE-2012-5204",
                "CVE-2012-5205", "CVE-2012-5206", "CVE-2012-5207", "CVE-2012-5208",
                "CVE-2012-5209", "CVE-2012-5210", "CVE-2012-5211", "CVE-2012-5212",
                "CVE-2012-5213");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-09-22 18:02:02 +0530 (Thu, 22 Sep 2016)");
  script_name("HP Intelligent Management Center (iMC) Multiple Vulnerabilities");

  script_tag(name:"summary", value:"HP Intelligent Management Center (iMC) is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to an unspecified
  vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to obtain sensitive information, modify data, or cause a denial
  of service or to execute arbitrary code.");

  script_tag(name:"affected", value:"HP Intelligent Management Center (iMC)
  prior to 5.2 E0401");

  script_tag(name:"solution", value:"Upgrade to HP Intelligent Management Center
  (iMC) version 5.2 E0401 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://h20566.www2.hp.com/portal/site/hpsc/public/kb/docDisplay?docId=emr_na-c03689276");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58673");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58675");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58672");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58676");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_hp_imc_detect.nasl");
  script_mandatory_keys("HPE/iMC/Win/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");
include("revisions-lib.inc");

if(!hpVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(revcomp(a: hpVer, b: "5.2.E0401") < 0)
{
  report = report_fixed_ver(installed_version:hpVer, fixed_version:"5.2 E0401");
  security_message(data:report);
  exit(0);
}
