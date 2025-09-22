# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100589");
  script_version("2024-06-28T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2010-04-20 13:41:39 +0200 (Tue, 20 Apr 2010)");
  script_cve_id("CVE-2009-4605");
  script_name("phpMyAdmin 'unserialize()' RCE Vulnerability");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_phpmyadmin_http_detect.nasl");
  script_mandatory_keys("phpMyAdmin/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37861");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2010-3.php");

  script_tag(name:"summary", value:"phpMyAdmin is prone to a vulnerability that lets attackers execute
  arbitrary code in the context of the webserver process.");

  script_tag(name:"impact", value:"This may facilitate unauthorized access or privilege escalation.
  Other attacks are also possible.");

  script_tag(name:"affected", value:"Versions prior to phpMyAdmin 3.0.0 or 2.11.10 are vulnerable.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"2.11.10" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.11.10/3.0.0" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
