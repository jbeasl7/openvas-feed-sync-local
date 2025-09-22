# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tufat:flashchat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800616");
  script_version("2024-03-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-03-01 14:37:10 +0000 (Fri, 01 Mar 2024)");
  script_tag(name:"creation_date", value:"2009-05-13 10:01:19 +0200 (Wed, 13 May 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-6799");
  script_name("FlashChat Role Filter Security Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_flashchat_detect.nasl");
  script_mandatory_keys("flashchat/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/32350");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31800");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/45974");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker bypass certain
  security restrictions and gain unauthorized administrative access to the affected application.");

  script_tag(name:"affected", value:"FlashChat Version 5.0.8 and prior.");

  script_tag(name:"insight", value:"This flaw is due to an error in the connection.php script.
  By setting the 's' parameter to a value of '7' a remote attacker could bypass
  the role filtering mechanism.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"FlashChat is prone to a security bypass vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less_equal( version:vers, test_version:"5.0.8" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"None" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
