# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ipass:ipass_open_mobile";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808732");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2015-0925");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2016-08-03 16:39:37 +0530 (Wed, 03 Aug 2016)");
  script_name("iPass Open Mobile Remote Code Execution Vulnerability - Windows");

  script_tag(name:"summary", value:"iPass Open Mobile is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a dll pathname in a
  crafted unicode string improperly handled by a subprocess reached through a
  named pipe.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  authenticated users to execute arbitrary code.");

  script_tag(name:"affected", value:"iPass Open Mobile prior to 2.4.5
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to iPass Open Mobile 2.4.5");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/110652");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72265");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_ipass_open_mobile_detect_win.nasl");
  script_mandatory_keys("IPass/OpenMobile/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!ipassVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:ipassVer, test_version:"2.4.5"))
{
  report = report_fixed_ver(installed_version:ipassVer, fixed_version:"2.4.5");
  security_message(data:report);
  exit(0);
}
