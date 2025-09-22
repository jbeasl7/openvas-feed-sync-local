# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php-fusion:php-fusion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15433");
  script_version("2025-06-03T05:40:40+0000");
  script_tag(name:"last_modification", value:"2025-06-03 05:40:40 +0000 (Tue, 03 Jun 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-2437", "CVE-2004-2438");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11296");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12425");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("PHP-Fusion <= 4.0.1 'members.php' SQLi Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("secpod_php_fusion_detect.nasl");
  script_mandatory_keys("php-fusion/detected");

  script_tag(name:"summary", value:"A vulnerability exists in PHP-Fusion that may allow an attacker
  to inject arbitrary SQL code and possibly execute arbitrary code, due to improper validation of
  user supplied input in the 'rowstart' parameter of script 'members.php'.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to the latest available version.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version:version, test_version:"4.0.1" ) ){
  report = report_fixed_ver( installed_version:version, fixed_version:"See references", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
