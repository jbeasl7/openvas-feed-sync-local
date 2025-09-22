# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:silverlight";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902986");
  script_version("2025-09-12T05:38:45+0000");
  script_cve_id("CVE-2013-3129", "CVE-2013-3131", "CVE-2013-3178");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2013-07-11 11:27:38 +0530 (Thu, 11 Jul 2013)");
  script_name("Microsoft Silverlight Remote Code Execution Vulnerabilities (2861561)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2861561");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60932");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60938");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60978");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2013/ms13-052");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl", "gb_ms_silverlight_detect.nasl");
  script_mandatory_keys("Microsoft/Silverlight/Installed");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to execute arbitrary code,
  bypass security mechanism and take complete control of an affected system.");

  script_tag(name:"affected", value:"Microsoft Silverlight version 5.");

  script_tag(name:"insight", value:"Multiple flaws due to:

  - Improper handling of TrueType font and multidimensional arrays of
    small structures

  - Improper Handling of null pointer");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS13-052.");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if( vers !~ "^5\." ) exit( 99 );

if( version_in_range( version:vers, test_version:"5.1", test_version2:"5.1.20512" ) ) {
  report = report_fixed_ver( installed_version:vers, vulnerable_range:"5.1 - 5.1.20512", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
