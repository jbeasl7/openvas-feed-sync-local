# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802871");
  script_version("2025-09-12T05:38:45+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2012-2034", "CVE-2012-2035", "CVE-2012-2036", "CVE-2012-2037",
                "CVE-2012-2039", "CVE-2012-2038", "CVE-2012-2040");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-14 16:05:35 +0000 (Fri, 14 Feb 2025)");
  script_tag(name:"creation_date", value:"2012-06-20 10:16:16 +0530 (Wed, 20 Jun 2012)");
  script_name("Adobe Flash Player Multiple Vulnerabilities (Jun 2012) - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49388");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53887");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1027139");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb12-14.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Win/Installed");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to bypass certain security
  restrictions, execute arbitrary code in the context of the browser or cause
  a denial of service (memory corruption) via unspecified vectors.");
  script_tag(name:"affected", value:"Adobe Flash Player version before 10.3.183.20 and 11.x through 11.2.202.235
  on Windows.");
  script_tag(name:"insight", value:"Multiple errors are caused,

  - When parsing ActionScript.

  - Within NPSWF32.dll when parsing certain tags.

  - In the 'SoundMixer.computeSpectrum()' method, which can be exploited to
    bypass the same-origin policy.

  - In the installer allows planting a binary file.");
  script_tag(name:"solution", value:"Update to Adobe Flash Player version 10.3.183.20 or 11.3.300.257 or later.");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");
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

if( version_is_less( version:vers, test_version:"10.3.183.20" ) ||
    version_in_range( version:vers, test_version:"11.0", test_version2:"11.2.202.235" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"10.3.183.20 or 11.3.300.257", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
