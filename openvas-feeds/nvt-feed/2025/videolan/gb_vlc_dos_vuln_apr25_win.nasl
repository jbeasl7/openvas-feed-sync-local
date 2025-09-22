# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:videolan:vlc_media_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836096");
  script_version("2025-04-03T05:39:15+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-04-03 05:39:15 +0000 (Thu, 03 Apr 2025)");
  script_tag(name:"creation_date", value:"2025-04-02 16:18:44 +0530 (Wed, 02 Apr 2025)");
  script_name("VLC Media Player < 3.0.20 DoS Vulnerability (Apr 2025) - Windows");

  script_tag(name:"summary", value:"VLC Media Player is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to conduct denial of service attacks.");

  script_tag(name:"affected", value:"VLC Media Player prior to version 3.0.20
  on Windows.");

  script_tag(name:"solution", value:"Update to version 3.0.20 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_vlc_media_player_detect_win.nasl");
  script_mandatory_keys("VLCPlayer/Win/Installed");
  script_xref(name:"URL", value:"https://www.videolan.org/security/sb-vlc3020.html");
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