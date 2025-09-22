# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:zohocorp:manageengine_applications_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812231");
  script_version("2025-09-17T05:39:26+0000");
  script_cve_id("CVE-2017-16846", "CVE-2017-16847", "CVE-2017-16848", "CVE-2017-16849",
                "CVE-2017-16850", "CVE-2017-16851");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-07 01:29:00 +0000 (Tue, 07 Aug 2018)");
  script_tag(name:"creation_date", value:"2017-11-29 18:51:22 +0530 (Wed, 29 Nov 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("ManageEngine Applications Manager < 13530 Multiple SQLi Vulnerabilities");

  script_tag(name:"summary", value:"ManageEngine Applications Manager is prone to multiple SQL
  injection (SQLi) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple input
  validation errors via,

  - 'method' parameter in '/manageApplications.do' script,

  - 'resourceid' parameter in '/showresource.do' script,

  - 'groupname' parameter in '/manageConfMons.do' script,

  - 'method' parameter in ' /MyPage.do' script,

  - 'resourceid' parameter in '/showresource.do' script,

  - 'widgetid' parameter in '/MyPage.do' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  remote attacker to execute arbitrary sql commands.");

  script_tag(name:"affected", value:"ManageEngine Applications Manager 13.");

  script_tag(name:"solution", value:"Update to version 13530 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://code610.blogspot.in/2017/11/more-sql-injections-in-manageengine.html");

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_manage_engine_appli_manager_detect.nasl");
  script_mandatory_keys("zohocorp/manageengine_applications_manager/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version =~ "^13" && version_is_less( version:version, test_version:"13530" ) ) {
  report = report_fixed_ver(installed_version:version, fixed_version:"13530", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
