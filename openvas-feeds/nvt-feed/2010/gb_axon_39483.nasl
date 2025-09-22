# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nch:axon_virtual_pbx";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100576");
  script_version("2024-03-04T14:37:58+0000");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2010-04-15 19:15:10 +0200 (Thu, 15 Apr 2010)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_name("Axon Virtual PBX 2.13 Multiple Remote Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_axon_virtual_pbx_web_detect.nasl");
  script_mandatory_keys("Axon-Virtual-PBX/www/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39483");

  script_tag(name:"impact", value:"An attacker may leverage these issues to cause a denial-of-service
  condition, run arbitrary script code in the browser of an unsuspecting user in the context of the
  affected application, steal cookie-based authentication credentials, perform certain administrative actions,
  gain unauthorized access to the affected application, delete certain data, and overwrite arbitrary files.
  Other attacks are also possible.");

  script_tag(name:"affected", value:"Axon 2.13 is vulnerable. Other versions may also be affected.");

  script_tag(name:"summary", value:"NCH Software Axon virtual PBX is prone to multiple remote
  vulnerabilities, including:

  - A cross-site scripting vulnerability.

  - A cross-site request forgery vulnerability.

  - An arbitrary file deletion vulnerability.

  - A directory traversal vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_equal( version:vers, test_version:"2.13" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"Unknown" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
