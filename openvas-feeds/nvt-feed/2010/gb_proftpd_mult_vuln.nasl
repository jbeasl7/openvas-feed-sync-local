# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:proftpd:proftpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801639");
  script_version("2024-03-04T05:10:24+0000");
  script_tag(name:"last_modification", value:"2024-03-04 05:10:24 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2010-11-30 12:42:12 +0100 (Tue, 30 Nov 2010)");
  script_cve_id("CVE-2010-3867", "CVE-2010-4221");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("ProFTPD Multiple Remote Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("FTP");
  script_dependencies("secpod_proftpd_server_detect.nasl");
  script_mandatory_keys("ProFTPD/Installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/42052");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44562");
  script_xref(name:"URL", value:"http://bugs.proftpd.org/show_bug.cgi?id=3519");
  script_xref(name:"URL", value:"http://bugs.proftpd.org/show_bug.cgi?id=3521");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-229/");

  script_tag(name:"summary", value:"ProFTPD is prone to multiple vulnerabilities.");
  script_tag(name:"insight", value:"- An input validation error within the 'mod_site_misc' module can be exploited
    to create and delete directories, create symlinks, and change the time of
    files located outside a writable directory.

  - A logic error within the 'pr_netio_telnet_gets()' function in 'src/netio.c'
    when processing user input containing the Telnet IAC escape sequence can be
    exploited to cause a stack-based buffer overflow by sending specially
    crafted input to the FTP or FTPS service.");
  script_tag(name:"affected", value:"ProFTPD versions prior to 1.3.3c");
  script_tag(name:"solution", value:"Upgrade to ProFTPD version 1.3.3c or later.");
  script_tag(name:"impact", value:"Successful exploitation may allow execution of arbitrary code or cause a
  denial-of-service.");

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

if( version_is_less( version:vers, test_version:"1.3.3c" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.3.3c" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
