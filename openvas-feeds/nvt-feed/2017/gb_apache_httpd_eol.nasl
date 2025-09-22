# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108085");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2017-02-27 11:48:20 +0100 (Mon, 27 Feb 2017)");
  script_name("Apache HTTP Server End of Life (EOL) Detection - Linux");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_dependencies("gb_apache_http_server_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/http_server/detected", "Host/runs_unixoide");

  script_xref(name:"URL", value:"https://archive.apache.org/dist/httpd/Announcement1.3.html");
  script_xref(name:"URL", value:"https://archive.apache.org/dist/httpd/Announcement2.0.html");
  script_xref(name:"URL", value:"https://www.apache.org/dist/httpd/Announcement2.2.html");
  script_xref(name:"URL", value:"https://en.wikipedia.org/wiki/Apache_HTTP_Server#Versions");

  script_tag(name:"summary", value:"The Apache HTTP Server version on the remote host has reached
  the End of Life (EOL) and should not be used anymore.");

  script_tag(name:"vuldetect", value:"Checks if an EOL version is present on the target host.");

  script_tag(name:"impact", value:"An EOL version of the Apache HTTP Server is not receiving any
  security updates from the vendor. Unfixed security vulnerabilities might be leveraged by an
  attacker to compromise the security of this host.");

  script_tag(name:"solution", value:"Update the Apache HTTP Server version on the remote host to a
  still supported version.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("date_func.inc");
include("eol_product.inc");
include("eol_shared.inc");
include("list_array_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

# nb: If "ServerTokens" is set to "Major" we're only getting a major version like "2" back.
# In this case we're just exiting here by using the stricter "version_regex".
if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"^[0-9]+\.[0-9]+" ) )
  exit( 0 );

version = infos["version"];

if( ret = product_reached_eol( cpe:CPE, version:version ) ) {
  report = eol_build_message( name:"Apache HTTP Server",
                              cpe:CPE,
                              version:version,
                              location:infos["location"],
                              eol_version:ret["eol_version"],
                              eol_date:ret["eol_date"],
                              eol_type:"prod" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
