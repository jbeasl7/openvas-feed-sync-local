# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:schneider_electric:indusoft_web_studio";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812215");
  script_version("2025-09-19T05:38:25+0000");
  script_cve_id("CVE-2017-14024");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-19 05:38:25 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-01 18:35:00 +0000 (Fri, 01 Dec 2017)");
  script_tag(name:"creation_date", value:"2017-11-17 16:09:59 +0530 (Fri, 17 Nov 2017)");
  script_name("InduSoft Web Studio Unspecified Stack Buffer Overflow Vulnerability - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_schneider_indusoft_consolidation.nasl");
  script_mandatory_keys("schneider_indusoft/installed");

  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-17-313-02");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101779");
  script_xref(name:"URL", value:"http://www.indusoft.com");

  script_tag(name:"summary", value:"InduSoft Web Studio is prone to an unspecified stack buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified
  stack-based buffer overflow error.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  a remote attacker to remotely execute code with high privileges.");

  script_tag(name:"affected", value:"Schneider Electric InduSoft Web Studio
  8.0 SP2 Patch 1 and prior versions on Windows.");

  script_tag(name:"solution", value:"Upgrade to InduSoft Web Studio
  version 8.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE)) exit(0);
studioVer = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:studioVer, test_version:"8.0.2.1"))
{
  report = report_fixed_ver( installed_version:studioVer, fixed_version:"IWS 8.1", install_path:path );
  security_message( data:report);
  exit(0);
}
