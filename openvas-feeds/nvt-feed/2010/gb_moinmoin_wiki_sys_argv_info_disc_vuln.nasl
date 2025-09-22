# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:moinmo:moinmoin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800171");
  script_version("2024-03-01T14:37:10+0000");
  script_cve_id("CVE-2010-0667");
  script_tag(name:"last_modification", value:"2024-03-01 14:37:10 +0000 (Fri, 01 Mar 2024)");
  script_tag(name:"creation_date", value:"2010-03-05 10:09:57 +0100 (Fri, 05 Mar 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("MoinMoin Wiki 'sys.argv' Information Disclosure Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moinmoin_wiki_detect.nasl");
  script_mandatory_keys("moinmoinWiki/installed");

  script_xref(name:"URL", value:"http://moinmo.in/SecurityFixes");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38116");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38242");
  script_xref(name:"URL", value:"http://marc.info/?l=oss-security&m=126625972814888&w=2");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2010/01/21/6");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2010/02/15/2");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain sensitive
  information.");
  script_tag(name:"affected", value:"MoinMoin Wiki version 1.9 before 1.9.1 on all platforms.");
  script_tag(name:"insight", value:"The flaw exists while handling sys.argv parameter when the GATEWAY_INTERFACE
  environment variable is set, which allows remote attackers to obtain
  sensitive information via unspecified vectors.");
  script_tag(name:"solution", value:"Upgrade to MoinMoin Wiki 1.9.1 or later.");
  script_tag(name:"summary", value:"MoinMoin Wiki is prone to an information disclosure vulnerability.");

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

if( version_in_range( version:vers, test_version:"1.9", test_version2:"1.9.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.9.1" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
