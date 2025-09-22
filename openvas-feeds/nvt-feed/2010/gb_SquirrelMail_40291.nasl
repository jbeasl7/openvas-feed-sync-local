# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:squirrelmail:squirrelmail";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100688");
  script_version("2024-03-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-03-01 14:37:10 +0000 (Fri, 01 Mar 2024)");
  script_tag(name:"creation_date", value:"2010-06-22 12:10:21 +0200 (Tue, 22 Jun 2010)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-08 19:56:01 +0000 (Thu, 08 Feb 2024)");
  script_cve_id("CVE-2010-1637");
  script_name("SquirrelMail 'mail_fetch' Remote Information Disclosure Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("squirrelmail_detect.nasl");
  script_mandatory_keys("squirrelmail/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40291");
  script_xref(name:"URL", value:"http://permalink.gmane.org/gmane.comp.security.oss.general/2935");
  script_xref(name:"URL", value:"http://permalink.gmane.org/gmane.comp.security.oss.general/3064");
  script_xref(name:"URL", value:"http://permalink.gmane.org/gmane.comp.security.oss.general/2936");
  script_xref(name:"URL", value:"http://conference.hitb.org/hitbsecconf2010dxb/materials/D1%20-%20Laurent%20Oudot%20-%20Improving%20the%20Stealthiness%20of%20Web%20Hacking.pdf#page=69");

  script_tag(name:"impact", value:"Attackers can exploit this issue to obtain potentially sensitive
  information that may lead to further attacks.");

  script_tag(name:"affected", value:"This issue affects SquirrelMail 1.4.x versions.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"SquirrelMail is prone to a remote information-disclosure
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_in_range( version:vers, test_version:"1.4", test_version2:"1.4.20" ) ||
    version_in_range( version:vers, test_version:"1.5", test_version2:"1.5.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.4.21/1.5.2" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
