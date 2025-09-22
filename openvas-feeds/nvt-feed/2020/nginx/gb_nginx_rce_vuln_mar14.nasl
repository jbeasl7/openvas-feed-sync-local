# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nginx:nginx";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117009");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2020-11-05 13:45:27 +0000 (Thu, 05 Nov 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2014-0088");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("nginx 1.5.10 'ngx_http_spdy_module' RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_nginx_consolidation.nasl");
  script_mandatory_keys("nginx/detected");

  script_tag(name:"summary", value:"nginx is prone to a remote code execution (RCE) vulnerability in
  the ngx_http_spdy_module module.");

  script_tag(name:"insight", value:"A bug in the experimental SPDY implementation in nginx was found,
  which might allow an attacker to corrupt worker process memory by using a specially crafted request,
  potentially resulting in arbitrary code execution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"The problem only affects nginx 1.5.10 on 32-bit platforms, compiled with
  the ngx_http_spdy_module module (which is not compiled by default), if the 'spdy' option of the 'listen'
  directive is used in a configuration file.");

  script_tag(name:"solution", value:"Update to version 1.5.11 or later.");

  script_xref(name:"URL", value:"https://nginx.org/en/CHANGES");
  script_xref(name:"URL", value:"https://mailman.nginx.org/pipermail/nginx-announce/2014/000132.html");

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

if( version_is_equal( version: version, test_version: "1.5.10" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.5.11", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
