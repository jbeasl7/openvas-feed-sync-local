# SPDX-FileCopyrightText: 2001 Noam Rathaus
# SPDX-FileCopyrightText: 2001 SecuriTeam
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:matt_wright:formmail";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10782");
  script_version("2024-03-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-03-01 14:37:10 +0000 (Fri, 01 Mar 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2001-0357");
  script_name("FormMail Insufficient Spam Protection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2001 SecuriTeam & Copyright (C) 2001 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("FormMail_detect.nasl");
  script_mandatory_keys("FormMail/installed");

  script_tag(name:"solution", value:"Upgrade to the latest version.");

  script_tag(name:"summary", value:"Matt Wright's FormMail CGI is installed on the remote host.

  FormMail.pl in FormMail 1.6 and earlier allows a remote attacker to send anonymous email (spam)
  by modifying the recipient and message parameters.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less_equal( version:vers, test_version:"1.6" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.7" );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );
