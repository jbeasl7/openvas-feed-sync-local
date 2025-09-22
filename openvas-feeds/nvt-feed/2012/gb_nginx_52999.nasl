# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nginx:nginx";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103470");
  script_cve_id("CVE-2012-2089");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_version("2023-07-25T05:05:58+0000");

  script_name("nginx 'ngx_http_mp4_module.c' Buffer Overflow Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52999");
  script_xref(name:"URL", value:"http://nginx.org/en/security_advisories.html");

  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-04-17 10:16:44 +0200 (Tue, 17 Apr 2012)");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("gb_nginx_consolidation.nasl");
  script_mandatory_keys("nginx/detected");

  script_tag(name:"summary", value:"nginx is prone to a buffer-overflow vulnerability because it fails to
  perform adequate boundary checks on user-supplied data.");

  script_tag(name:"impact", value:"Attackers may leverage this issue to execute arbitrary code in the
  context of the application. Failed attacks will cause denial-of-service conditions.");

  script_tag(name:"affected", value:"nginx versions 1.1.3 through 1.1.18 and 1.0.7 through 1.0.14 are
  vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

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

if( version =~ "^1\.1" ) {
  if( version_is_less( version: version, test_version: "1.1.19" ) ) {
    report = report_fixed_ver( installed_version: version, fixed_version: "1.1.19", install_path: location );
    security_message( port: port, data: report );
    exit( 0 );
  }
}

if( version =~ "^1\.0" ) {
  if( version_is_less( version: version, test_version: "1.0.15" ) ) {
    report = report_fixed_ver( installed_version: version, fixed_version: "1.0.15", install_path: location );
    security_message( port: port, data: report );
    exit( 0 );
  }
}

exit( 99 );
