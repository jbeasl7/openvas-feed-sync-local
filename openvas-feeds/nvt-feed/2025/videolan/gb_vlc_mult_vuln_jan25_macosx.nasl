# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:videolan:vlc_media_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834916");
  script_version("2025-01-31T05:37:27+0000");
  script_cve_id("CVE-2023-47359", "CVE-2023-47360");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-31 05:37:27 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-13 19:31:30 +0000 (Mon, 13 Nov 2023)");
  script_tag(name:"creation_date", value:"2025-01-27 21:31:58 +0530 (Mon, 27 Jan 2025)");
  script_name("VLC Media Player Multiple Vulnerabilities (Jan 2025) - Mac OS X");

  script_tag(name:"summary", value:"VLC Media Player is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2023-47359: Heap buffer overflow in MMSH module

  - CVE-2023-47360: Integer underflow in MMSH module");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to cause a memory corruption by exploiting an incorrect offset read and
  conduct denial of service attacks.");

  script_tag(name:"affected", value:"VLC Media Player prior to version 3.0.20
  on Mac OS X.");

  script_tag(name:"solution", value:"Update to version 3.0.20 or later.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_vlc_media_player_detect_macosx.nasl");
  script_mandatory_keys("VLC/Media/Player/MacOSX/Version");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-47359");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-47360");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"3.0.20")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"3.0.20", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);