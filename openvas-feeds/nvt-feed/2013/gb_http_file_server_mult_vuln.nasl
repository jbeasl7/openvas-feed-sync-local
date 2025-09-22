# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:httpfilesever:hfs";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803171");
  script_version("2024-03-01T14:37:10+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-03-01 14:37:10 +0000 (Fri, 01 Mar 2024)");
  script_tag(name:"creation_date", value:"2013-02-19 15:17:57 +0530 (Tue, 19 Feb 2013)");
  script_name("HTTP File Server Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://1337day.com/exploit/20345");
  script_xref(name:"URL", value:"http://bot24.blogspot.in/2013/02/http-file-server-v2x-xss-and-file.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_http_file_server_detect.nasl");
  script_mandatory_keys("hfs/Installed");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to insert arbitrary
  HTML and script code and execute arbitrary PHP code.");
  script_tag(name:"affected", value:"HttpFileServer version 2.2f and prior");
  script_tag(name:"insight", value:"- An input passed to 'search' parameter is not properly sanitized
  before being returned to the user.

  - An error due to the '~upload ' script allowing the upload of files with
  arbitrary extensions to a folder inside the webroot can be exploited to
  execute arbitrary PHP code by uploading a malicious PHP script.");
  script_tag(name:"solution", value:"Update to version 2.3 or later.");
  script_tag(name:"summary", value:"HTTP File Server is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! version = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:version, test_version:"2.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.3" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
