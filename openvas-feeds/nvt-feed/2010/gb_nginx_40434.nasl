# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nginx:nginx";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100658");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-05-31 18:31:53 +0200 (Mon, 31 May 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("nginx Space String Remote Source Code Disclosure Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40434");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_nginx_consolidation.nasl");
  script_mandatory_keys("nginx/detected");

  script_tag(name:"solution", value:"Reportedly, the issue is fixed in version 0.8.36. Please contact the
  vendor for more information.");

  script_tag(name:"summary", value:"nginx is prone to a remote source code-disclosure vulnerability
  because it fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to view the source code of
  files in the context of the server process, which may aid in further attacks.");

  script_tag(name:"affected", value:"This issue affects nginx versions prior to 0.8.36.");

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

if( version_is_less( version: version, test_version: "0.8.36" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "0.8.36", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
