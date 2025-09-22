# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:smartertools:smartermail";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803793");
  script_version("2024-03-01T14:37:10+0000");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-03-01 14:37:10 +0000 (Fri, 01 Mar 2024)");
  script_tag(name:"creation_date", value:"2014-01-20 13:17:30 +0530 (Mon, 20 Jan 2014)");
  script_name("SmarterMail Enterprise and Standard Stored XSS vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_smartermail_detect.nasl");
  script_mandatory_keys("SmarterMail/installed");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/31017");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64970");
  script_xref(name:"URL", value:"http://cxsecurity.com/issue/WLB-2014010100");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/124792/smartermail11-xss.txt");

  script_tag(name:"summary", value:"SmarterMail Enterprise/Standard is prone to stored cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw due to an improper validation, input passed via the email body before
  returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML or
  script code.");

  script_tag(name:"affected", value:"SmarterMail Enterprise and Standard versions 11.x and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less_equal( version:vers, test_version:"11.7" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"No fix available" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
