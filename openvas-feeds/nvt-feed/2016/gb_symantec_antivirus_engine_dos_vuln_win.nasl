# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:symantec:anti-virus_engine";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808534");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2016-2208");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-01 03:08:00 +0000 (Thu, 01 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-07-04 14:15:06 +0530 (Mon, 04 Jul 2016)");
  script_name("Symantec Antivirus Engine Denial of Service Vulnerability - Windows");

  script_tag(name:"summary", value:"Symantec Antivirus Engine is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the
  kernel component via a malformed PE header file.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code or cause a denial of service.");

  script_tag(name:"affected", value:"Symantec Anti-Virus Engine (AVE) 20151.1
  before 20151.1.1.4.");

  script_tag(name:"solution", value:"Update to Symantec Anti-Virus Engine (AVE)
  version 20151.1.1.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&amp;pvid=security_advisory&amp;suid=20160516_00");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/90653");

  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_symantec_antivirus_engine_detect_win.nasl");
  script_mandatory_keys("Symantec/Antivirus/Engine/Ver");
  script_xref(name:"URL", value:"https://support.symantec.com/en_US/article.TECH103088.html");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!sepVer = get_app_version(cpe:CPE)){
  exit(0);
}

##https://support.symantec.com/en_US/article.TECH95856.html
if(version_is_less(version:sepVer, test_version:"20151.1.1.4"))
{
  report = report_fixed_ver(installed_version:sepVer, fixed_version:"20151.1.1.4");
  security_message(data:report);
  exit(0);
}
