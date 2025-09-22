# SPDX-FileCopyrightText: 2015 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:vaadin:vaadin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105179");
  script_version("2025-09-09T14:09:45+0000");
  script_tag(name:"last_modification", value:"2025-09-09 14:09:45 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2015-01-22 12:00:00 +0100 (Thu, 22 Jan 2015)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Vaadin Framework < 6.6.7 / 6.7.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_vaadin_http_detect.nasl");
  script_mandatory_keys("vaadin/detected");

  script_tag(name:"summary", value:"Vaadin Framework is prone to multiple cross-site scripting,
  information disclosure, and security bypass vulnerabilities because the application fails to
  properly sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Directory traversal through AbstractApplicationServlet.serveStaticResourcesInVAADIN()

  - CSRF / XSS through separator injection

  - Contributory XSS: Possibility to inject HTML/javascript in system error messages

  - Contributory XSS: possibility for injection in certain components");

  script_tag(name:"impact", value:"Successful exploitation could allow:

  - A remote attacker to leverage the cross-site scripting issues to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site.
  This may allow the attacker to steal cookie-based authentication credentials and launch other
  attacks.

  - Exploiting the information disclosure issues allows the attacker to view local files within the
  context of the Web server process.

  - Exploiting the security bypass vulnerability allows attackers to bypass security restrictions
  and obtain sensitive information or perform unauthorized actions.");

  script_tag(name:"affected", value:"Vaadin Framework version 6.0.0 through 6.6.6.");

  script_tag(name:"solution", value:"Update to version 6.6.7, 6.7.0 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49854");
  script_xref(name:"URL", value:"http://www.vaadin.com/download/release/6.6/6.6.7/release-notes.html");
  script_xref(name:"URL", value:"http://www.vaadin.com/download/release/6.7/6.7.0/release-notes.html");

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

if( version_in_range( version:version, test_version:"6.0.0", test_version2:"6.6.6" ) ) {
  report = report_fixed_ver(installed_version:version, fixed_version:"6.6.7", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
