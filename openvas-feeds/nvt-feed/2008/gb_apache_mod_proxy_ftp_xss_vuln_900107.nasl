# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900107");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2008-2939");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_name("Apache HTTP Server 'mod_proxy_ftp' Wildcard Characters XSS Vulnerability");
  script_dependencies("gb_apache_http_server_consolidation.nasl");
  script_mandatory_keys("apache/http_server/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/495180");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30560");
  script_xref(name:"URL", value:"http://httpd.apache.org/docs/2.0/mod/mod_proxy_ftp.html");
  script_xref(name:"URL", value:"http://svn.apache.org/viewvc?view=rev&revision=682871");
  script_xref(name:"URL", value:"http://svn.apache.org/viewvc?view=rev&revision=682868");

  script_tag(name:"summary", value:"Apache HTTP Server is prone to a cross-site scripting vulnerability.");

  script_tag(name:"insight", value:"Input passed to the module mod_proxy_ftp with wildcard character
  is not properly sanitized before returning to the user.");

  script_tag(name:"affected", value:"Apache HTTP Server versions 2.0.0 to 2.0.63 and 2.2.0 to 2.2.9.");

  script_tag(name:"solution", value:"Fixed is available in the SVN repository, please see the references
  for more information.");

  script_tag(name:"impact", value:"Remote attackers can execute arbitrary script code.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"^[0-9]+\.[0-9]+\.[0-9]+" ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_in_range( version:vers, test_version:"2.0.0", test_version2:"2.0.63" ) ||
    version_in_range( version:vers, test_version:"2.2.0", test_version2:"2.2.9" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );