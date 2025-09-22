# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:videolan:vlc_media_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815547");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2019-13602", "CVE-2019-14437", "CVE-2019-14438", "CVE-2019-14498",
                "CVE-2019-14533", "CVE-2019-14534", "CVE-2019-14535", "CVE-2019-14776",
                "CVE-2019-14777", "CVE-2019-14778", "CVE-2019-14970");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-08-20 15:30:25 +0530 (Tue, 20 Aug 2019)");
  script_name("VLC Media Player Multiple Vulnerabilities (sb-vlc308) - Mac OS X");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("gb_vlc_media_player_detect_macosx.nasl");
  script_mandatory_keys("VLC/Media/Player/MacOSX/Version");

  script_xref(name:"URL", value:"https://www.videolan.org/security/sb-vlc308.html");

  script_tag(name:"summary", value:"VLC Media Player is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Buffer overflow in the MKV demuxer

  - Buffer overflow in the FAAD decoder

  - Buffer overflow in the OGG demuxer

  - Buffer overflow in the ASF demuxer

  - A use after free in the MKV demuxer

  - A use after free in the ASF demuxer

  - Fix a couple of integer underflows in the MP4 demuxer

  - A null dereference in the dvdnav demuxer

  - A null dereference in the ASF demuxer

  - A null dereference in the AVI demuxer

  - A division by zero in the CAF demuxer

  - A division by zero in the ASF demuxer");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause a denial of
  service condition and execute arbitrary code.");

  script_tag(name:"affected", value:"VLC Media Player versions prior to 3.0.8 on Mac OS X.");

  script_tag(name:"solution", value:"Update to version 3.0.8 or later.");

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

if(version_is_less(version:vers, test_version:"3.0.8")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"3.0.8", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
