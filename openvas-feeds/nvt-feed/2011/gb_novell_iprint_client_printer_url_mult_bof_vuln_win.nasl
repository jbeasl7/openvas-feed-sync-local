# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:novell:iprint";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801951");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2011-06-13 15:28:04 +0200 (Mon, 13 Jun 2011)");
  script_cve_id("CVE-2011-1699", "CVE-2011-1700", "CVE-2011-1701", "CVE-2011-1702",
                "CVE-2011-1703", "CVE-2011-1704", "CVE-2011-1705", "CVE-2011-1706",
                "CVE-2011-1707", "CVE-2011-1708");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Novell iPrint Client 'printer-url' Multiple BOF Vulnerabilities - Windows");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1025606");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-172/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-173/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-174/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-175/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-176/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-177/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-178/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-179/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-180/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-181/");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("secpod_novell_prdts_detect_win.nasl");
  script_mandatory_keys("Novell/iPrint/Installed");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code under
  the context of the browser.");
  script_tag(name:"affected", value:"Novell iPrint Client version prior to 5.64 on windows.");
  script_tag(name:"insight", value:"The flaws exist within the 'nipplib' component which is used by both the
  ActiveX and Netscape compatible browser plugins. When handling the various
  parameters from the user specified printer-url the process blindly copies
  user supplied data into a fixed-length buffer on the heap.");
  script_tag(name:"solution", value:"Upgrade to Novell iPrint Client 5.64 or later.");
  script_xref(name:"URL", value:"http://download.novell.com/Download?buildid=6_bNby38ERg~");
  script_tag(name:"summary", value:"Novell iPrint Client is prone to multiple buffer overflow vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"5.64" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.64", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
