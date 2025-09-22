# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:videolan:vlc_media_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817259");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2020-08-11 18:28:36 +0530 (Tue, 11 Aug 2020)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-19 16:15:00 +0000 (Fri, 19 Jun 2020)");

  script_cve_id("CVE-2020-13428");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("VLC Media Player < 3.0.11 DoS Vulnerability - Mac OS X");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_vlc_media_player_detect_macosx.nasl");
  script_mandatory_keys("VLC/Media/Player/MacOSX/Version");

  script_tag(name:"summary", value:"VLC Media Player is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"A heap based overflow in the hxxx_AnnexB_to_xVC
  function in modules/packetizer/hxxx_nal.c allows remote attacker to cause
  denial of service (application crash) or execute arbitrary code
  via a crafted H.264 Annex-B video file.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to trigger
  either a crash of VLC or execute arbitrary code.");

  script_tag(name:"affected", value:"VideoLAN VLC Media Player before version 3.0.11 on Mac OS X.");

  script_tag(name:"solution", value:"Update to version 3.0.11 or later.");

  script_xref(name:"URL", value:"https://www.videolan.org/security/sb-vlc3011.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"3.0.11")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"3.0.11", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
