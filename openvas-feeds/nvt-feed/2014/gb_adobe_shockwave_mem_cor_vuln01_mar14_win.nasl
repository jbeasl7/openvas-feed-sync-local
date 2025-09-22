# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:shockwave_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804517");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2014-0505");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-03-21 14:04:57 +0530 (Fri, 21 Mar 2014)");
  script_name("Adobe Shockwave Player Memory Corruption Vulnerability (Mar 2014) - Windows");

  script_tag(name:"summary", value:"Adobe Shockwave Player is prone to a memory corruption vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaw is due to an unspecified error.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code, cause
memory corruption and compromise a user's system.");
  script_tag(name:"affected", value:"Adobe Shockwave Player version before 12.1.0.150 on Windows.");
  script_tag(name:"solution", value:"Upgrade to version 12.1.0.150 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/57277");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66182");
  script_xref(name:"URL", value:"https://www.hkcert.org/my_url/en/alert/14031701");
  script_xref(name:"URL", value:"http://helpx.adobe.com/security/products/shockwave/apsb14-10.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_shockwave_player_detect.nasl");
  script_mandatory_keys("Adobe/ShockwavePlayer/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less(version:vers, test_version:"12.1.0.150")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"12.1.0.150");
  security_message(port:0, data:report);
  exit(0);
}
