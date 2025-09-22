# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nginx:nginx";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100277");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-10-01 18:57:31 +0200 (Thu, 01 Oct 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("nginx Proxy DNS Cache Domain Spoofing Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36438");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/506541");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/506543");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("gb_nginx_consolidation.nasl");
  script_mandatory_keys("nginx/detected");

  script_tag(name:"summary", value:"nginx is prone to a vulnerability that may allow attackers to spoof
  domains because the software fails to properly compare domains when referencing an internal DNS cache.");

  script_tag(name:"impact", value:"This issue can be exploited when nginx is configured to act as a forward
  proxy, but this is a nonstandard and unsupported configuration. Attacks against other configurations may
  also be possible.

  Successful exploits may allow remote attackers to intercept traffic intended for legitimate websites, which may
  aid in further attacks.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
  to a newer release, disable respective features, remove the product or replace the product by another one.");

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

if( version_in_range( version: version, test_version: "0.8", test_version2: "0.8.15" ) ||
    version_in_range( version: version, test_version: "0.7", test_version2: "0.7.62" ) ||
    version_in_range( version: version, test_version: "0.6", test_version2: "0.6.39" ) ||
    version_in_range( version: version, test_version: "0.5", test_version2: "0.5.38" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
