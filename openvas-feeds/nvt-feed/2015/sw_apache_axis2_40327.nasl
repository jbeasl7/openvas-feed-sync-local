# SPDX-FileCopyrightText: 2015 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:apache:axis2";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111005");
  script_version("2023-12-20T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-12-20 05:05:58 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2015-03-17 08:00:00 +0100 (Tue, 17 Mar 2015)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2010-2103");
  script_name("Apache Axis2 < 1.5.2 'engagingglobally' XSS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_dependencies("gb_apache_axis2_http_detect.nasl");
  script_mandatory_keys("apache/axis2/detected");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/12689");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40327");

  script_tag(name:"summary", value:"Apache Axis2 is prone to a cross-site scripting (XSS)
  vulnerability because it fails to properly sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected site. This may help the
  attacker steal cookie-based authentication credentials and to launch other attacks.");

  script_tag(name:"affected", value:"The issue affects versions prior to 1.5.2.");

  script_tag(name:"solution", value:"The vendor has released fixes. Please see the references for
  more information.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

path = infos["location"];
vers = infos["version"];

if( version_is_less( version:vers, test_version:"1.5.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.5.2", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
