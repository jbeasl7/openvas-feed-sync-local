# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:lussumo:vanilla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800757");
  script_version("2024-03-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-03-01 14:37:10 +0000 (Fri, 01 Mar 2024)");
  script_tag(name:"creation_date", value:"2010-04-16 16:17:26 +0200 (Fri, 16 Apr 2010)");
  script_cve_id("CVE-2010-1337");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Lussumo Vanilla 'definitions.php' RFI Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_lussumo_vanilla_detect.nasl");
  script_mandatory_keys("Lussumo/Vanilla/detected");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/57147");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38889");
  script_xref(name:"URL", value:"http://www.packetstormsecurity.com/1003-exploits/vanilla-rfi.txt");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary
  code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"Lussumo Vanilla version 1.1.10 and prior.");

  script_tag(name:"insight", value:"The flaw is due to an error in the 'include' and
  'Configuration[LANGUAGE]' parameters, which allows remote attackers to send
  a specially-crafted URL request to the 'definitions.php' script.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"summary", value:"Lussumo Vanilla is prone to remote file include (RFI) vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"WillNotFix");

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

if( version_is_less_equal( version:ver, test_version:"1.1.10" ) ) {
  report = report_fixed_ver( installed_version:ver, fixed_version:"WillNotFix", install_path:dir );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
