# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:videolan:vlc_media_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834633");
  script_version("2024-10-04T15:39:55+0000");
  script_cve_id("CVE-2024-46461");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-10-04 15:39:55 +0000 (Fri, 04 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-10-02 10:44:02 +0530 (Wed, 02 Oct 2024)");
  script_name("VLC Media Player DoS Vulnerability (Oct24) - Mac OS X");

  script_tag(name:"summary", value:"VLC Media Player is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a heap based
  overflow in VLC Media Player.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to trigger either a crash of VLC or an arbitrary code execution with the
  privileges of the target user.");

  script_tag(name:"affected", value:"VLC Media Player prior to version 3.0.21
  on Mac OS X.");

  script_tag(name:"solution", value:"Update to version 3.0.21 or later.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_vlc_media_player_detect_macosx.nasl");
  script_mandatory_keys("VLC/Media/Player/MacOSX/Version");
  script_xref(name:"URL", value:"https://www.videolan.org/security/sb-vlc3021.html");
  script_xref(name:"URL", value:"https://securityonline.info/vlc-media-player-update-needed-cve-2024-46461-discovered/");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"3.0.21")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"3.0.21", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
