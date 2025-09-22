# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nch:axon_virtual_pbx";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900984");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-11-26 06:39:46 +0100 (Thu, 26 Nov 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-4038");
  script_name("Axon Virtual PBX Multiple XSS Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_axon_virtual_pbx_detect.nasl", "gb_axon_virtual_pbx_web_detect.nasl");
  script_mandatory_keys("Axon-Virtual-PBX/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/37157/");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/387986.php");

  script_tag(name:"impact", value:"Successful exploitation will let the attackers execute arbitrary HTML and
  script code in the affected user's browser session.");

  script_tag(name:"affected", value:"Axon Virtual PBX version 2.10 and 2.11.");

  script_tag(name:"insight", value:"The input passed into 'onok' and 'oncancel' parameters in the logon program
  is not properly sanitised before being returned to the user.");

  script_tag(name:"solution", value:"Upgrade to Axon Virtual PBX version 2.13 or later.");

  script_tag(name:"summary", value:"Axon Virtual PBX is prone to multiple cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_in_range( version:vers, test_version:"2.10", test_version2:"2.11" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.13" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );