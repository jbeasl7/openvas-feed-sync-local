# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nginx:nginx";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801636");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-11-18 06:30:08 +0100 (Thu, 18 Nov 2010)");
  script_cve_id("CVE-2009-2629");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("nginx HTTP Request Remote Buffer Overflow Vulnerability");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/180065");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36384");
  script_xref(name:"URL", value:"http://sysoev.ru/nginx/patch.180065.txt");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_nginx_consolidation.nasl");
  script_mandatory_keys("nginx/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary code
  within the context of the affected application. Failed exploit attempts will result in a denial-of-service
  condition.");

  script_tag(name:"affected", value:"nginx versions 0.1.0 through 0.5.37, 0.6.x before 0.6.39, 0.7.x before
  0.7.62 and 0.8.x before 0.8.15.");

  script_tag(name:"insight", value:"The flaw is due to an error in 'src/http/ngx_http_parse.c' which
  allows remote attackers to execute arbitrary code via crafted HTTP requests.");

  script_tag(name:"solution", value:"Update to nginx versions 0.5.38, 0.6.39, 0.7.62 or 0.8.15.");

  script_tag(name:"summary", value:"nginx is prone to a buffer-overflow vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe: CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "0.1.0", test_version2: "0.5.37" ) ||
    version_in_range( version: version, test_version: "0.6.0", test_version2: "0.6.38" ) ||
    version_in_range( version: version, test_version: "0.7.0", test_version2: "0.7.61" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "0.5.37/0.6.38/0.7.61", install_path: location );
  security_message( port: port, data:report );
  exit( 0 );
}

exit( 99 );
