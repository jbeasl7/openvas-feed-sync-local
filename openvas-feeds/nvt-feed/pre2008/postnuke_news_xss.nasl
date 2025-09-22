# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:postnuke:postnuke";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14727");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Post-Nuke News Module XSS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_dependencies("secpod_zikula_detect.nasl");
  script_mandatory_keys("postnuke/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5809");

  script_tag(name:"summary", value:"The the 'News' module of Post-Nuke is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"impact", value:"An attacker may use these flaws to steal the cookies of the
  legitimate users of this web site.");

  script_tag(name:"solution", value:"Upgrade to the latest version of postnuke.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

ver = infos["version"];
dir = infos["location"];

if( version_is_less_equal( version:ver, test_version:"0.721" ) ) {
  report = report_fixed_ver( installed_version:ver, fixed_version:"See references", install_path:dir );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );