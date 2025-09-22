# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpbb:phpbb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100086");
  script_version("2024-03-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-03-01 14:37:10 +0000 (Fri, 01 Mar 2024)");
  script_tag(name:"creation_date", value:"2009-03-29 17:14:47 +0200 (Sun, 29 Mar 2009)");
  script_cve_id("CVE-2008-6506");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("phpBB Account Re-Activation Authentication Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("phpbb_detect.nasl");
  script_mandatory_keys("phpBB/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32842");

  script_tag(name:"impact", value:"Attackers can exploit this vulnerability to gain unauthorized access
  to the affected application, which may aid in further attacks.");

  script_tag(name:"affected", value:"Versions prior to phpBB 3.0.4 are vulnerable.");

  script_tag(name:"solution", value:"Update to version 3.0.4 or later.");

  script_tag(name:"summary", value:"According to its version number, the remote version of phpbb
  is prone to an authentication-bypass vulnerability because it fails
  to properly enforce privilege requirements on some operations.");

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

if( version_is_less( version:vers, test_version:"3.0.4" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.0.4" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
