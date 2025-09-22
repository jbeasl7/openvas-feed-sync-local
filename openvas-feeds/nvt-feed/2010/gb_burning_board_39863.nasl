# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:woltlab:burning_board_lite";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100629");
  script_version("2025-09-17T05:39:26+0000");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"creation_date", value:"2010-05-06 13:19:12 +0200 (Thu, 06 May 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Woltlab Burning Board <= 1.0.2 Arbitrary File Upload Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("secpod_woltlab_burning_board_detect.nasl");
  script_mandatory_keys("WoltLabBurningBoard/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39863");
  script_xref(name:"URL", value:"http://www.woltlab.de/products/burning_board/index_en.php");

  script_tag(name:"summary", value:"Woltlab Burning Board is prone to a vulnerability that lets attackers
  upload arbitrary files because the application fails to adequately sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to upload arbitrary code
  and run it in the context of the webserver process. This may facilitate unauthorized access or privilege
  escalation. Other attacks are also possible.");

  script_tag(name:"affected", value:"Burning Board Lite 1.0.2 is affected. Other versions may also be
  vulnerable.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less_equal( version:vers, test_version:"1.0.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"WillNotFix", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
