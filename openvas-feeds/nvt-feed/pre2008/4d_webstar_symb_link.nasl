# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14241");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-0698");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_name("4D WebStar Symbolic Link Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Remote file access");
  script_dependencies("gb_webstar_detect.nasl");
  script_mandatory_keys("4d/webstar/detected");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to 4D WebStar 5.3.3 or later.");

  script_tag(name:"summary", value:"4D WebStar is reportedly vulnerable to a local symbolic link vulnerability.");

  script_tag(name:"insight", value:"This issue is due to a design error that causes the application
  to open files without properly verifying their existence or their absolute location.");

  script_tag(name:"impact", value:"Successful exploitation of this issue will allow an attacker to write
  to arbitrary files writable by the affected application, facilitating privilege escalation.");

  script_xref(name:"URL", value:"http://www.atstake.com/research/advisories/2004/a071304-1.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10714");

  exit(0);
}

CPE = "cpe:/a:4d:webstar";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "5.3.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.3.3", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
