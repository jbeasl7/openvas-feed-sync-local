# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:synology:synology_photo_station";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812358");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2017-12072");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:22:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-12-21 15:28:05 +0530 (Thu, 21 Dec 2017)");
  script_name("Synology Photo Station Cross-Site Scripting Vulnerability (Synology_SA_17_80)");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_synology_photo_station_detect.nasl");
  script_mandatory_keys("synology_photo_station/installed");

  script_xref(name:"URL", value:"https://www.synology.com/en-global/support/security/Synology_SA_17_80");

  script_tag(name:"summary", value:"Synology Photo Station is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to insufficient
  validation of input passed to 'PixlrEditorHandler.php' script via the 'id'
  parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  authenticated users to inject arbitrary web scripts or HTML code.");

  script_tag(name:"affected", value:"Synology Photo Station before before
  6.8.0-3456");

  script_tag(name:"solution", value:"Upgrade to Photo Station version
  6.8.0-3456 or above.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!synport = get_app_port(cpe: CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:synport, exit_no_version:TRUE)) exit(0);
synVer = infos["version"];
synpath = infos["location"];

if(version_is_less(version:synVer, test_version: "6.8.0-3456")){
  report = report_fixed_ver(installed_version:synVer, fixed_version:"6.8.0-3456", install_path:synpath);
  security_message(port:synport, data: report);
}

exit(0);
