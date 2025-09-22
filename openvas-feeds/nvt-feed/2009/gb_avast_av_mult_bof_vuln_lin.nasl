# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:avast:antivirus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800599");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-07-09 10:58:23 +0200 (Thu, 09 Jul 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-6846");
  script_name("avast! AntiVirus Multiple BOF Vulnerabilities - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_avast_av_detect_lin.nasl");
  script_mandatory_keys("avast/antivirus/detected");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/47251");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32747");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/382096.php");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2008/3460");

  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary code in the context
  of affected application, and can cause denial of service.");

  script_tag(name:"affected", value:"avast! Linux Home Edition 1.0.8-2 and prior on Linux.");

  script_tag(name:"insight", value:"Multiple buffer overflow errors occur while processing malformed ISO or
  RPM files as the application fails to perform adequate bounds check on
  files before copying them into an insufficiently sized buffer.");

  script_tag(name:"solution", value:"Upgrade to avast! Linux Home Edition latest version.");

  script_tag(name:"summary", value:"avast! AntiVirus is prone to multiple Buffer Overflow Vulnerabilities.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version:version, test_version:"1.0.8" ) ) {
  report = report_fixed_ver(installed_version:version, vulnerable_range:"Less than or equal to 1.0.8", install_path:location);
  security_message(port:0, data:report);
  exit( 0 );
}

exit( 99 );
