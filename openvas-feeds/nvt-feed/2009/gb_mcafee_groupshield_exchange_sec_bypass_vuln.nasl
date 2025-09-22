# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mcafee:groupshield";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800619");
  script_version("2025-09-16T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"creation_date", value:"2009-05-22 10:20:17 +0200 (Fri, 22 May 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1491");
  script_name("McAfee GroupShield for Exchange X-Header Security Bypass Vulnerability");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/50354");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34949");
  script_xref(name:"URL", value:"http://www.nmrc.org/~thegnome/blog/apr09");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("SMTP problems");
  script_dependencies("gb_mcafee_groupshield_detect.nasl");
  script_mandatory_keys("McAfee/GroupShield/Exchange/Installed");

  script_tag(name:"impact", value:"Successful exploits will let the attacker craft malicious
  contents inside the X-Header and can bypass antivirus detection and launch
  further attacks into the affected system.");

  script_tag(name:"affected", value:"McAfee GroupShield for Exchange version 6.0.616.102 and prior.");

  script_tag(name:"insight", value:"This flaw is due to failure in scanning X-Headers while sending
  mail messages.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"McAfee GroupShield for Microsoft Exchange is prone to X-Header Security Bypass Vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0) ;

vers = infos["version"];
path = infos["location"];

if( version_is_less_equal( version:vers, test_version:"6.0.616.102" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"None", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
