# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:coldfusion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804443");
  script_version("2025-01-15T05:38:11+0000");
  script_cve_id("CVE-2013-3350");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-15 05:38:11 +0000 (Wed, 15 Jan 2025)");
  script_tag(name:"creation_date", value:"2014-05-06 15:14:38 +0530 (Tue, 06 May 2014)");
  script_name("Adobe ColdFusion Components (CFC) Denial Of Service Vulnerability (APSB13-19)");

  script_tag(name:"summary", value:"Adobe ColdFusion is prone to a denial of service
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in ColdFusion Components (CFC) public methods
  which can be accessed via WebSockets.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause denial of service
  conditions.");

  script_tag(name:"affected", value:"Adobe ColdFusion 10 before Update 11.");

  script_tag(name:"solution", value:"Upgrade to Adobe ColdFusion 10 Update 11 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1028757");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61042");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb13-19.html");
  script_xref(name:"URL", value:"http://blogs.coldfusion.com/post.cfm/coldfusion-10-websocket-vulnerebility");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_adobe_coldfusion_http_detect.nasl");
  script_mandatory_keys("adobe/coldfusion/detected");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"^[0-9]+\.[0-9]+")) # nb: The HTTP Detection VT might only extract the major version like 11 or 2021
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_in_range(version:version, test_version:"10.0", test_version2:"10.0.11.285436")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"See references", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
