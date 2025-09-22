# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:synology:synology_photo_station";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812224");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2017-11161", "CVE-2017-11162", "CVE-2017-12071");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:21:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-11-23 13:23:39 +0530 (Thu, 23 Nov 2017)");
  script_name("Synology Photo Station Multiple Vulnerabilities (SA_17_35)");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_synology_photo_station_detect.nasl");
  script_mandatory_keys("synology_photo_station/installed", "synology_photo_station/psv");

  script_xref(name:"URL", value:"https://www.synology.com/en-global/support/security/Synology_SA_17_35_PhotoStation");

  script_tag(name:"summary", value:"Synology Photo Station is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple
  input validation errors in 'url' parameter while downloading and reading
  arbitrary files, insufficient input validation in article_id parameter to
  'label.php' script and insufficient input validation in type parameter to
  'synotheme.php' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  remote attacker to execute arbitrary SQL commands, read arbitrary files
  and download arbitrary local files.");

  script_tag(name:"affected", value:"Synology Photo Station before 6.7.4-3433
  and 6.3-2968.");

  script_tag(name:"solution", value:"Upgrade to Photo Station to 6.7.4-3433
  or (6.3-2968 for DSM 5.2 users).");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!synport = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location( cpe:CPE, port:synport, exit_no_version:TRUE)) exit(0);
synVer = infos["version"];
synpath = infos["location"];

if(version_is_less(version:synVer, test_version: "6.3-2968")){
  fix = "6.3-2968";
}

else if(version_in_range(version:synVer, test_version:"6.7", test_version2:"6.7.3-3432") ||
   version_in_range(version:synVer, test_version:"6.6", test_version2:"6.6.3-3347") ||
   version_in_range(version:synVer, test_version:"6.5", test_version2:"6.5.3-3226") ||
   version_in_range(version:synVer, test_version:"6.4", test_version2:"6.4-3166")){
  fix = "6.7.3-3433";
}

if(fix){
  report = report_fixed_ver(installed_version:synVer, fixed_version:fix, install_path:synpath);
  security_message(port:synport, data: report);
}

exit(0);
