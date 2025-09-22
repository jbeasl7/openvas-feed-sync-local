# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900122");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-09-25 09:10:39 +0200 (Thu, 25 Sep 2008)");
  script_cve_id("CVE-2008-3636");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("Privilege escalation");
  script_name("Apple iTunes < 8.0 Local Privilege Escalation Vulnerability (Sep 2008)");
  script_dependencies("gb_apple_itunes_smb_login_detect.nasl");
  script_mandatory_keys("apple/itunes/detected");

  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2008/Sep/1020839.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31089");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce//2008/Sep/msg00001.html");

  script_tag(name:"summary", value:"Apple iTunes is prone to a privilege escalation vulnerability.");

  script_tag(name:"insight", value:"The flaw is due to integer overflow error in a third-party
  driver bundled with iTune.");

  script_tag(name:"affected", value:"Apple iTunes versions prior to 8.0 on Windows.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Update to version 8.0 or later.");

  script_tag(name:"impact", value:"Successful exploitation will allow local users to obtain elevated
  privileges thus compromising the affected system.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit(0);

vers = infos["version"];
path = infos["location"];

if( egrep( pattern:"^([0-6]\..*|7\.[0-9](\..*)?)$", string:vers ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"8.0", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
