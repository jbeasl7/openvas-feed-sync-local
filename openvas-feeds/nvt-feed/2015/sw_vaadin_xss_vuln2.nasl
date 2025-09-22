# SPDX-FileCopyrightText: 2015 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:vaadin:vaadin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105183");
  script_version("2025-09-09T14:09:45+0000");
  script_tag(name:"last_modification", value:"2025-09-09 14:09:45 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2015-01-22 12:00:00 +0100 (Thu, 22 Jan 2015)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Vaadin Framework 6.0.0 - 6.8.13 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_vaadin_http_detect.nasl");
  script_mandatory_keys("vaadin/detected");

  script_tag(name:"summary", value:"Vaadin Framework is prone to a cross-site scripting (XSS)
  vulnerability because the application fails to properly sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Proper escaping of the src-attribute on the client side was not
  ensured when using icons for OptionGroup items.");

  script_tag(name:"impact", value:"This could potentially, in certain situations, allow a malicious
  user to inject content, such as javascript, in order to perform a cross-site scripting (XSS)
  attack.");

  script_tag(name:"affected", value:"Vaadin Framework version 6.0.0 through 6.8.13.");

  script_tag(name:"solution", value:"Update to version 6.8.14 or later.");

  script_xref(name:"URL", value:"http://www.vaadin.com/download/release/6.8/6.8.14/release-notes.html");

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

if( version_in_range( version:version, test_version:"6.0.0", test_version2:"6.8.13" ) ) {
  report = report_fixed_ver(installed_version:version, fixed_version:"6.8.14", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
