# SPDX-FileCopyrightText: 2015 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:magentocommerce:magento";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105225");
  script_version("2024-03-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-03-01 14:37:10 +0000 (Fri, 01 Mar 2024)");
  script_tag(name:"creation_date", value:"2015-02-23 12:00:00 +0100 (Mon, 23 Feb 2015)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Magento Multiple HTML Injection Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_magento_detect.nasl");
  script_mandatory_keys("magento/installed");

  script_tag(name:"summary", value:"Magento is prone to multiple HTML injection vulnerabilities because it fails to properly sanitize user-supplied input.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"impact", value:"Attacker-supplied HTML or JavaScript code could run in the context of the
  affected site, potentially allowing the attacker to steal cookie-based authentication
  credentials and to control how the site is rendered to the user. Other attacks are also possible.");
  script_tag(name:"affected", value:"Magento 1.3.2.4 is vulnerable. Other versions may also be affected.");
  script_tag(name:"solution", value:"Check for updated versions of Magento.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37611");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less_equal( version:vers, test_version:"1.3.2.4" ) ) {
  report = report_fixed_ver( installed_version:vers, vulnerable_range:"Less than or equal to 1.3.2.4" );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
