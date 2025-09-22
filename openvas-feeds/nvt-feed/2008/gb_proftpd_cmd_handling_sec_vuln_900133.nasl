# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:proftpd:proftpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900133");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-09-26 07:36:49 +0200 (Fri, 26 Sep 2008)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-4242");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("FTP");
  script_name("ProFTPD Long Command Handling Security Vulnerability");
  script_dependencies("secpod_proftpd_server_detect.nasl");
  script_mandatory_keys("ProFTPD/Installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/31930/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31289");
  script_xref(name:"URL", value:"http://bugs.proftpd.org/show_bug.cgi?id=3115");

  script_tag(name:"summary", value:"ProFTPD Server is prone to a cross-site request forgery (CSRF) vulnerability.");

  script_tag(name:"insight", value:"The flaw exists due to the application truncating an overly long FTP command,
  and improperly interpreting the remainder string as a new FTP command.");

  script_tag(name:"affected", value:"ProFTPD Server version prior 1.3.2rc3.");

  script_tag(name:"solution", value:"Upgrade to the latest version 1.3.2rc3.");

  script_tag(name:"impact", value:"This can be exploited to execute arbitrary FTP commands on another
  user's session privileges.");

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

if( version_is_less( version:vers, test_version:"1.3.2.rc3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.3.2rc3" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
