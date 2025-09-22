# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:xpolog:xpolog_center";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105808");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("XpoLog Center <= 6.4469 Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://zeroscience.mk/en/vulnerabilities/ZSL-2016-5334.php");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Ask the vendor for an update.");

  script_tag(name:"summary", value:"XpoLog Center is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Multiple flaws exist including cross-site scripting (XSS), Open
  Redirection and Cross-Site Request Forgery (CSRF) vulnerabilities.");

  script_tag(name:"affected", value:"XpoLog Center up to and including version 6.4469 is known to be
  affected.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2016-07-12 14:56:54 +0200 (Tue, 12 Jul 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_xpolog_detect.nasl");
  script_mandatory_keys("xpolog_center/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less_equal( version:vers, test_version:"6.4469" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"Ask vendor" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
