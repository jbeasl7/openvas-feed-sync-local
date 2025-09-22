# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nginx:nginx";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803222");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2011-4963");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-02-01 13:21:59 +0530 (Fri, 01 Feb 2013)");

  script_name("nginx Security Bypass Vulnerability - Windows");

  script_xref(name:"URL", value:"http://secunia.com/advisories/50912");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55920");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/77244");
  script_xref(name:"URL", value:"http://english.securitylab.ru/lab/PT-2012-06");
  script_xref(name:"URL", value:"http://nginx.org/en/security_advisories.html");
  script_xref(name:"URL", value:"http://mailman.nginx.org/pipermail/nginx-announce/2012/000086.html");
  script_xref(name:"URL", value:"http://blog.ptsecurity.com/2012/06/vulnerability-in-nginx-eliminated.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_nginx_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("nginx/detected", "Host/runs_windows");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to gain unauthorized access to
  restricted resources via specially crafted HTTP requests containing NTFS extended attributes.");

  script_tag(name:"affected", value:"nginx versions 0.7.52 through 1.2.0 and 1.3.0 on Windows.");

  script_tag(name:"insight", value:"The flaw is due to an error when processing HTTP requests for resources
  defined via the 'location' directive.");

  script_tag(name:"solution", value:"Update to nginx version 1.3.1 or 1.2.1 or later.");

  script_tag(name:"summary", value:"nginx is prone to a security bypass vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe: CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "0.7.52", test_version2: "1.2.0" ) ||
    version_is_equal( version: version, test_version: "1.3.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "See advisory", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
