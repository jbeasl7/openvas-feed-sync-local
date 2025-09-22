# SPDX-FileCopyrightText: 2004 Netteksecure Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sun:jre";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12244");
  script_version("2025-09-16T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-0651");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10301");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Sun Java Runtime Environment < 1.4.2_04 DoS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 Netteksecure Inc.");
  script_family("Windows");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");

  script_tag(name:"solution", value:"Upgrade to SDK and JRE 1.4.2_04.");

  script_tag(name:"summary", value:"The remote Windows machine is running a Java SDK or JRE version
  1.4.2_03 and prior which is vulnerable to a DoS attack.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( ereg( pattern:"^1\.4\.([01]|2_0[0-3])", string:vers ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.4.2_04", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
