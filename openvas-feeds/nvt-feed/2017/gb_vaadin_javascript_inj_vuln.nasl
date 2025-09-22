# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vaadin:vaadin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107226");
  script_version("2025-09-09T14:09:45+0000");
  script_tag(name:"last_modification", value:"2025-09-09 14:09:45 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-06-23 12:00:00 +0100 (Fri, 23 Jun 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Vaadin Framework 7.7.6 - 7.7.9 Javascript Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_vaadin_http_detect.nasl");
  script_mandatory_keys("vaadin/detected");

  script_tag(name:"summary", value:"Vaadin Framework is prone to a Javascript injection
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The exploit is due to inappropriate rendering in the
  combobox.");

  script_tag(name:"impact", value:"Successful exploiting this vulnerability will allow an attacker
  to inject malicious javascript code.");

  script_tag(name:"affected", value:"Vaadin Framework version 7.7.6 through 7.7.9.");
  script_tag(name:"solution", value:"Update to version 8.0.2 or later.");

  script_xref(name:"URL", value:"https://github.com/vaadin/framework/issues/8731");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2017/Jun/27");

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

if( version_in_range( version:version, test_version:"7.7.6", test_version2:"7.7.9" ) ) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.2", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
