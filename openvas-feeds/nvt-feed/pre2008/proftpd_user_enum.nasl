# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:proftpd:proftpd";

#  Ref: LSS Security

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15484");
  script_version("2024-03-04T05:10:24+0000");
  script_tag(name:"last_modification", value:"2024-03-04 05:10:24 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11430");
  script_cve_id("CVE-2004-1602");
  script_name("ProFTPD < 1.2.11 Remote User Enumeration");
  script_category(ACT_GATHER_INFO);
  script_family("FTP");
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_dependencies("secpod_proftpd_server_detect.nasl");
  script_mandatory_keys("ProFTPD/Installed");

  script_tag(name:"summary", value:"The remote ProFTPD server is as old or older than 1.2.10");
  script_tag(name:"insight", value:"It is possible to determine which user names are valid on the remote host
  based on timing analysis attack of the login procedure.");
  script_tag(name:"impact", value:"An attacker may use this flaw to set up a list of valid usernames for a
  more efficient brute-force attack against the remote host.");
  script_tag(name:"solution", value:"Upgrade to a newer version");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"1.2.11" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.2.11" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
