# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:videolan:vlc_media_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805426");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2014-9598", "CVE-2014-9597");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-01-27 17:11:51 +0530 (Tue, 27 Jan 2015)");
  script_name("VLC Media Player Multiple Vulnerabilities -02 (Jan 2015) - Linux");

  script_tag(name:"summary", value:"VLC Media player is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Improper input sanitization by 'picture_Release' function in misc/picture.c.

  - Improper input sanitization by 'picture_pool_Delete' function in
    misc/picture_pool.c.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code or cause a denial of service.");

  script_tag(name:"affected", value:"VideoLAN VLC media player 2.1.5 on
  Linux.");

  script_tag(name:"solution", value:"Upgrade to VideoLAN VLC media player
  version 2.2.0-rc2 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Jan/72");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72106");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72105");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/130004/");

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_vlc_media_player_detect_lin.nasl");
  script_mandatory_keys("VLCPlayer/Lin/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vlcVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_equal(version:vlcVer, test_version:"2.1.5"))
{
  report = 'Installed version: ' + vlcVer + '\n' +
             'Fixed version:     ' + "2.2.0-rc2" + '\n';
  security_message(data:report );
  exit(0);
}
