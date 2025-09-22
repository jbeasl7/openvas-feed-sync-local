# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:avast:avast_pro_antivirus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811021");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2017-8308", "CVE-2017-8307");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-05-05 13:59:15 +0530 (Fri, 05 May 2017)");
  script_name("Avast Pro Antivirus Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Avast Pro Antivirus is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to design errors in
  the application. Using LPC interface API exposed by the AvastSVC.exe Windows
  service it is possible to delete arbitrary file, replace arbitrary file and
  launch predefined binaries.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct a denial-of-service condition, execute arbitrary code and bypass
  certain security features on the affected system.");

  script_tag(name:"affected", value:"Avast Pro Antivirus version prior to
  version 17.0");

  script_tag(name:"solution", value:"Upgrade to Avast Pro Antivirus version
  17.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.trustwave.com/Resources/Security-Advisories/Advisories/Multiple-Vulnerabilities-in-Avast-Antivirus/?fid=9201");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98084");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98086");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_avast_pro_detect.nasl");
  script_mandatory_keys("Avast/Pro_Antivirus/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!avastVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:avastVer, test_version:"17.0"))
{
  report = report_fixed_ver(installed_version:avastVer, fixed_version:"17.0");
  security_message(data:report);
  exit(0);
}
