# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sawmill:sawmill";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100507");
  script_version("2024-03-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-03-01 14:37:10 +0000 (Fri, 01 Mar 2024)");
  script_tag(name:"creation_date", value:"2010-02-24 18:35:31 +0100 (Wed, 24 Feb 2010)");
  script_cve_id("CVE-2010-1079");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Sawmill Unspecified Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38387");
  script_xref(name:"URL", value:"http://www.sawmill.net");
  script_xref(name:"URL", value:"http://www.sawmill.net/version_history7.html");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_sawmill_detect.nasl");
  script_mandatory_keys("sawmill/installed");

  script_tag(name:"solution", value:"An update is available. Please see the references for details.");
  script_tag(name:"summary", value:"Sawmill is prone to a cross-site scripting vulnerability because it
 fails to properly sanitize user-supplied input.");
  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script code
 in the browser of an unsuspecting user in the context of the affected
 site. This may allow the attacker to steal cookie-based authentication
 credentials and to launch other attacks.");
  script_tag(name:"affected", value:"This issue affects versions prior to 7.2.18.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version: vers, test_version: "7.2.18" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"7.2.18" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
