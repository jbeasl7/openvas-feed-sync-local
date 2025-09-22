# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:coldfusion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804442");
  script_version("2025-01-15T05:38:11+0000");
  script_cve_id("CVE-2013-5326", "CVE-2013-5328");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-01-15 05:38:11 +0000 (Wed, 15 Jan 2025)");
  script_tag(name:"creation_date", value:"2014-05-06 13:50:21 +0530 (Tue, 06 May 2014)");
  script_name("Adobe ColdFusion Multiple Vulnerabilities (APSB13-27)");

  script_tag(name:"summary", value:"Adobe ColdFusion is prone to multiple vulnerabilities");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are  due to:

  - Certain unspecified input is not properly sanitised before being
  returned to the user. This can be exploited to execute arbitrary HTML
  and script code in a user's browser session in context of an affected site.

  - An unspecified error can be exploited to gain unauthorised read access.
  No further information is currently available.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct cross-site scripting
  attacks and bypass certain security restrictions.");

  script_tag(name:"affected", value:"Adobe ColdFusion 10 before Update 12.");

  script_tag(name:"solution", value:"Upgrade to Adobe ColdFusion 10 Update 12 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/295276");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63681");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63682");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/88739");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb13-27.html");
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

if(version_in_range(version:version, test_version:"10.0", test_version2:"10.0.12.286679")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"See references", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
