# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_media_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100551");
  script_version("2024-03-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-03-01 14:37:10 +0000 (Fri, 01 Mar 2024)");
  script_tag(name:"creation_date", value:"2010-03-25 19:45:44 +0100 (Thu, 25 Mar 2010)");
  script_cve_id("CVE-2009-3792", "CVE-2009-3791");
  script_name("Adobe Flash Media Server Multiple Vulnerabilities (APSB09-18)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_adobe_fms_detect.nasl");
  script_mandatory_keys("Adobe/FMS/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37420");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37419");
  script_xref(name:"URL", value:"https://web.archive.org/web/20220308111305/https://www.adobe.com/support/security/bulletins/apsb09-18.html");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");
  script_tag(name:"impact", value:"Exploiting the directory-traversal issue can allow an attacker to load
  arbitrary Dynamic Linked Libraries (DLLs) present on the server. This
  could help the attacker launch further attacks.

  Successful exploits of the denial-of-service vulnerability will allow
  attackers to consume an excessive amount of CPU resources, denying
  service to legitimate users.");
  script_tag(name:"summary", value:"Adobe Flash Media Server is prone to a directory-traversal
  vulnerability and to a remote denial-of-service vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_in_range( version:vers, test_version:"3.5", test_version2:"3.5.2" ) ||
    version_is_less( version:vers, test_version:"3.0.5" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See vendor advisory" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
