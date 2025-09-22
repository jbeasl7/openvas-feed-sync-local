# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:novell:iprint";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902328");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2011-01-03 16:00:43 +0100 (Mon, 03 Jan 2011)");
  script_cve_id("CVE-2010-4321");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Novell iPrint Client 'ienipp.ocx' ActiveX Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-256/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44966");
  script_xref(name:"URL", value:"http://www.novell.com/support/viewContent.do?externalId=7007234");

  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_novell_prdts_detect_win.nasl");
  script_mandatory_keys("Novell/iPrint/Installed");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code in
  the context of the application.");
  script_tag(name:"affected", value:"Novell iPrint Client version 5.52");
  script_tag(name:"insight", value:"The flaw is due to an error in 'ienipp.ocx' in the method
  'GetDriverSettings' which blindly copies user supplied data into a
  fixed-length buffer on the stack.");
  script_tag(name:"solution", value:"Upgrade to Novell iPrint Client version 5.56 or later.");
  script_xref(name:"URL", value:"http://download.novell.com/Download?buildid=JV7fd0tFHHM~");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Novell iPrint Client is prone to a buffer overflow vulnerability.");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if( version_is_equal( version:vers, test_version:"5.52" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.56", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
