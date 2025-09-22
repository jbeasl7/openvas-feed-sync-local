# SPDX-FileCopyrightText: 2015 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:apache:axis2";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111004");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2015-03-17 08:00:00 +0100 (Tue, 17 Mar 2015)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_cve_id("CVE-2012-5785", "CVE-2012-4418", "CVE-2012-5351");

  script_name("Apache Axis2 <= 1.6.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_dependencies("gb_apache_axis2_http_detect.nasl");
  script_mandatory_keys("apache/axis2/detected");

  script_tag(name:"summary", value:"Apache Axis2 is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2012-5785: a security bypass vulnerability because the application fails to properly
  validate SSL certificates from the server

  - CVE-2012-4418: a security vulnerability involving XML signature wrapping

  - CVE-2012-5351: a SAML assertion that lacks a Signature element, aka a
  'Signature exclusion attack'");

  script_tag(name:"impact", value:"Successfully exploiting these issues allows attackers to:

  - CVE-2012-5785: perform man-in-the-middle attacks or impersonate trusted servers, which will aid
  in further attacks

  - CVE-2012-4418: may allow unauthenticated attackers to construct specially crafted messages that
  can be successfully verified and contain arbitrary content. This may aid in further attacks

  - CVE-2012-5351: allows remote attackers to forge messages and bypass authentication");

  script_tag(name:"affected", value:"The issue affects versions up to 1.6.2.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"https://issues.apache.org/jira/browse/AXIS2C-1607");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56408");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55508");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");

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

if( version_is_less_equal( version:vers, test_version:"1.6.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"None", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 0 );
