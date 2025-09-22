# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nginx:nginx";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103344");
  script_cve_id("CVE-2011-4315");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("nginx DNS Resolver Remote Heap Buffer Overflow Vulnerability");

  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-11-21 11:12:32 +0100 (Mon, 21 Nov 2011)");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("gb_nginx_consolidation.nasl");
  script_mandatory_keys("nginx/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50710");
  script_xref(name:"URL", value:"http://www.nginx.org/en/CHANGES");
  script_xref(name:"URL", value:"http://trac.nginx.org/nginx/changeset/4268/nginx");

  script_tag(name:"solution", value:"Vendor updates are available. Please see the references for more
  information.");

  script_tag(name:"summary", value:"nginx is prone to a remote heap-based buffer-overflow vulnerability.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allows attackers to execute
  arbitrary code in the context of the vulnerable application. Failed
  exploit attempts will result in a denial-of-service condition.");

  script_tag(name:"affected", value:"Versions prior to nginx 1.0.10 are vulnerable.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version:"1.0.10" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.0.10", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
