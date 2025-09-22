# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:squirrelmail:squirrelmail";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14217");
  script_version("2024-03-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-03-01 14:37:10 +0000 (Fri, 01 Mar 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10450");
  script_cve_id("CVE-2004-0639");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name:"OSVDB", value:"8292");
  script_name("SquirrelMail From Email header HTML injection vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("squirrelmail_detect.nasl");
  script_mandatory_keys("squirrelmail/installed");

  script_tag(name:"solution", value:"Upgrade to SquirrelMail 1.2.11 or later or wrap the call to
  sqimap_find_displayable_name in printMessageInfo in functions/mailbox_display.php with a call to htmlentities.");

  script_tag(name:"summary", value:"The target is running at least one instance of SquirrelMail whose
  version number is between 1.2.0 and 1.2.10 inclusive.");

  script_tag(name:"insight", value:"Such versions do not properly sanitize From headers, leaving users
  vulnerable to XSS attacks. Further, since SquirrelMail displays From headers when listing a folder,
  attacks does not require a user to actually open a message, only view the folder listing.

  For example, a remote attacker could effectively launch a DoS against
  a user by sending a message with a From header such as:

  From:<!--<>(-->John Doe<script>document.cookie='PHPSESSID=xxx<semicolon> path=/'<semicolon></script><>

  which rewrites the session ID cookie and effectively logs the user out.");

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

if( version_in_range( version:vers, test_version:"1.2.0", test_version2:"1.2.10" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.2.11" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
