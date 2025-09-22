# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:avast:antivirus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107739");
  script_version("2024-02-15T05:05:40+0000");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-11-01 15:43:17 +0100 (Fri, 01 Nov 2019)");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-12572");

  script_name("Avast Free Antivirus < 19.1.2360 Information Disclosure Vulnerability - Windows");

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_avast_av_detect_win.nasl");
  script_mandatory_keys("avast/antivirus_free/detected");

  script_tag(name:"summary", value:"Avast Free Antivirus is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Avast Free Antivirus stores user credentials in memory upon login.");

  script_tag(name:"impact", value:"The vulnerability allows local users to obtain sensitive information
  by dumping AvastUI.exe application memory and parsing the data.");

  script_tag(name:"affected", value:"Avast Free Antivirus prior to version 19.1.2360.");

  script_tag(name:"solution", value:"Update to Avast Free Antivirus version 19.1.2360 or later.");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/151590/Avast-Anti-Virus-Local-Credential-Disclosure.html");

  exit(0);
}

include( "version_func.inc" );
include( "host_details.inc" );

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"19.1.2360" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"19.1.2360", install_path:path );
  security_message( data:report, port:0 );
  exit( 0 );
}

exit( 99 );
