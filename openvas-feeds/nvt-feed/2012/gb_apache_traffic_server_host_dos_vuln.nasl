# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:traffic_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902664");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2012-0256");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-03-28 13:46:18 +0530 (Wed, 28 Mar 2012)");
  script_name("Apache Traffic Server HTTP Host Header DoS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_apache_traffic_server_http_detect.nasl");
  script_mandatory_keys("apache/ats/detected");

  script_xref(name:"URL", value:"http://securitytracker.com/id/1026847");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52696");
  script_xref(name:"URL", value:"https://secunia.com/advisories/48509/");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2012/Mar/117");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2012/Mar/260");
  script_xref(name:"URL", value:"https://www.cert.fi/en/reports/2012/vulnerability612884.html");
  script_xref(name:"URL", value:"http://mail-archives.apache.org/mod_mbox/www-announce/201203.mbox/%3C4F6B6649.9000507@apache.org%3E");

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to cause the application
  to crash, creating a denial of service condition.");

  script_tag(name:"affected", value:"Apache Traffic Server 2.0.x, 3.0.x before 3.0.4, 3.1.x before 3.1.3.");

  script_tag(name:"insight", value:"The flaw is due to an improper allocation of heap memory when
  processing HTTP request with a large 'HOST' header value and can be
  exploited to cause a denial of service via a specially crafted packet.");

  script_tag(name:"solution", value:"Upgrade to Apache Traffic Server 3.0.4 or 3.1.3 or later.");

  script_tag(name:"summary", value:"Apache Traffic Server is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit(0);

vers = infos["version"];
path = infos["location"];

if( version_in_range( version:vers, test_version:"2.0", test_version2:"2.0.9" ) ||
    version_in_range( version:vers, test_version:"3.0", test_version2:"3.0.3" ) ||
    version_in_range( version:vers, test_version:"3.1", test_version2:"3.1.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.0.4/3.1.3", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
