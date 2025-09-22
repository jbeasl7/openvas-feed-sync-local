# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nginx:nginx";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103469");
  script_cve_id("CVE-2012-1180");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_version("2025-01-17T15:39:18+0000");

  script_name("nginx 'ngx_cpystrn()' Information Disclosure Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52578");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=803856");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2012/Mar/65");
  script_xref(name:"URL", value:"http://trac.nginx.org/nginx/changeset/4530/nginx");

  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2012-04-17 10:03:32 +0200 (Tue, 17 Apr 2012)");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_tag(name:"solution_type", value:"VendorFix");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("gb_nginx_consolidation.nasl");
  script_mandatory_keys("nginx/detected");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"nginx is prone to an information disclosure vulnerability.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to harvest sensitive information that
  may lead to further attacks.");

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
  if( version_is_less( version: version, test_version: "1.1.17" ) ) {
    report = report_fixed_ver( installed_version: version, fixed_version: "1.1.17", install_path: location );
    security_message( port: port, data: report );
    exit( 0 );
  }
}

if( version =~ "^1\.0" ) {
  if( version_is_less( version: version, test_version: "1.0.14" ) ) {
    report = report_fixed_ver( installed_version: version, fixed_version: "1.0.14", install_path: location );
    security_message( port: port, data: report );
    exit( 0 );
  }
}

exit( 99 );
