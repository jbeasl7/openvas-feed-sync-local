# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:squirrelmail:squirrelmail";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100759");
  script_version("2024-03-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-03-01 14:37:10 +0000 (Fri, 01 Mar 2024)");
  script_tag(name:"creation_date", value:"2010-08-13 12:44:16 +0200 (Fri, 13 Aug 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2010-2813");
  script_name("SquirrelMail Remote Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("squirrelmail_detect.nasl");
  script_mandatory_keys("squirrelmail/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42399");
  script_xref(name:"URL", value:"http://www.squirrelmail.org/security/issue/2010-07-23");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=618096");

  script_tag(name:"impact", value:"An attacker can exploit this issue to cause the application to consume
  excessive disk space, resulting in denial-of-service conditions.");

  script_tag(name:"affected", value:"SquirrelMail versions prior and up to 1.4.20 are vulnerable. Others
  may also be affected.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"SquirrelMail is prone to a remote denial-of-service vulnerability
  because it fails to properly handle certain user requests.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"1.4.21" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.4.21" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
