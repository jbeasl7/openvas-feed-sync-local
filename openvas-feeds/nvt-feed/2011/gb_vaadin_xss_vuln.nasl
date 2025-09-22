# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vaadin:vaadin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902330");
  script_version("2025-09-09T14:09:45+0000");
  script_tag(name:"last_modification", value:"2025-09-09 14:09:45 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2011-02-05 04:12:38 +0100 (Sat, 05 Feb 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2011-0509");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Vaadin Framework 6.0.0 - 6.4.8 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_vaadin_http_detect.nasl");
  script_mandatory_keys("vaadin/detected");

  script_tag(name:"summary", value:"Vaadin Framework is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Input passed to the 'URL' parameter in 'index.php', is not
  properly sanitised before being returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary HTML and script code in a user's browser session in the context of an affected
  application.");

  script_tag(name:"affected", value:"Vaadin Framework version 6.0.0 through 6.4.8.");

  script_tag(name:"solution", value:"Update to version 6.4.9 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/42879");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/64626");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45779");
  script_xref(name:"URL", value:"http://www.vaadin.com/download/release/6.4/6.4.9/release-notes.html");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range( version:version, test_version:"6.0.0", test_version2:"6.4.8" ) ) {
  report = report_fixed_ver(installed_version:version, fixed_version:"6.4.9", install_path:location );
  security_message(port: port, data: report);
  exit( 0 );
}

exit( 99 );
