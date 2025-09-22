# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:traffic_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100797");
  script_version("2023-08-11T05:05:41+0000");
  script_tag(name:"last_modification", value:"2023-08-11 05:05:41 +0000 (Fri, 11 Aug 2023)");
  script_tag(name:"creation_date", value:"2010-09-10 15:25:30 +0200 (Fri, 10 Sep 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2010-2952");
  script_name("Apache Traffic Server Remote DNS Cache Poisoning Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_apache_traffic_server_http_detect.nasl");
  script_mandatory_keys("apache/ats/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43111");
  script_xref(name:"URL", value:"https://issues.apache.org/jira/browse/TS-425");
  script_xref(name:"URL", value:"http://www.nth-dimension.org.uk/pub/NDSA20100830.txt.asc");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"Apache Traffic Server is prone to a remote DNS cache-poisoning
  vulnerability.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to divert data from a legitimate
  site to an attacker-specified site.

  Successful exploits will allow the attacker to manipulate cache data, potentially facilitating
  man-in-the-middle, site-impersonation, or denial-of-service attacks.");

  script_tag(name:"affected", value:"Versions prior to Apache Traffic Server 2.0.1.");

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

if( version_is_less( version:vers, test_version:"2.0.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.0.1", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
