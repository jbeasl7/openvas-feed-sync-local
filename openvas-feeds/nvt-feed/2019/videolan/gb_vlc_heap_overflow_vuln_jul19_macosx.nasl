# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:videolan:vlc_media_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815256");
  script_version("2025-09-12T05:38:45+0000");
  script_cve_id("CVE-2019-13615");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-07-19 09:05:52 +0530 (Fri, 19 Jul 2019)");
  script_name("VLC Media Player 'libebml' Library Heap Overflow Vulnerability (Jul 2019) - Mac OS X");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("gb_vlc_media_player_detect_macosx.nasl");
  script_mandatory_keys("VLC/Media/Player/MacOSX/Version");

  script_xref(name:"URL", value:"https://trac.videolan.org/vlc/ticket/22474");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/109304");
  script_xref(name:"URL", value:"https://github.com/Matroska-Org/libebml/commit/05beb69ba60acce09f73ed491bb76f332849c3a0");
  script_xref(name:"URL", value:"https://github.com/Matroska-Org/libebml/commit/b66ca475be967547af9a3784e720fbbacd381be6");
  script_xref(name:"URL", value:"https://github.com/Matroska-Org/libebml/compare/release-1.3.5...release-1.3.6");

  script_tag(name:"summary", value:"VLC Media Player is prone to a heap-based buffer over-read vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a heap-based buffer
  over-read error in EbmlElement::FindNextElement of the 'libebml' library as
  used by VLC Media Player.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to
  cause denial of service condition and launch further attacks using specially
  crafted files.");

  script_tag(name:"affected", value:"libebml before 1.3.6, as used in the MKV module
  in VLC Media Player binaries before 3.0.3 on Mac OS X.");

  script_tag(name:"solution", value:"Update VLC Media Player to version 3.0.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"3.0.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"3.0.3", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
