# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:coldfusion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804445");
  script_version("2025-01-15T05:38:11+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2013-0625", "CVE-2013-0629");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-01-15 05:38:11 +0000 (Wed, 15 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:45:54 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2014-05-06 16:22:22 +0530 (Tue, 06 May 2014)");
  script_name("Adobe ColdFusion Multiple Vulnerabilities (APSB13-03)");

  script_tag(name:"summary", value:"Adobe ColdFusion is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The CFIDE/componentutils/cfcexplorer.cfc script not properly sanitizing
  user input, specifically directory traversal attacks supplied via the
  'path' parameter when 'method' is set to:'getcfcinhtml' and 'name' is
  set to 'CFIDE.adminapi.administrator'.

  - The 'ScheduledURL' variable allows specifying an arbitrary resource to save
  to system as specified by the 'publish_file' variable and then schedule this
  task to be executed at a set time.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to disclose the contents of
  arbitrary files on the system and execute arbitrary code.");

  script_tag(name:"affected", value:"Adobe ColdFusion 9.0, 9.0.1, 9.0.2, and 10.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/24946");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57164");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57165");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb13-03.html");
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

if(version_is_equal(version:version, test_version:"9.0.0.251028") ||
   version_is_equal(version:version, test_version:"9.0.1.274733") ||
   version_is_equal(version:version, test_version:"9.0.2.282541") ||
   version_is_equal(version:version, test_version:"10.0.0.282462")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"See references", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
