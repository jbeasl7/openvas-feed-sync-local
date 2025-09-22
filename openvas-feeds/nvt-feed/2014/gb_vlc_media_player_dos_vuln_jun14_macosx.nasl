# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:videolan:vlc_media_player";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804614");
  script_version("2024-02-16T05:06:55+0000");
  script_cve_id("CVE-2014-3441");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-06-04 11:10:43 +0530 (Wed, 04 Jun 2014)");
  script_name("VLC Media Player Denial of Service Vulnerability -01 (Jun 2014) - Mac OS X");

  script_tag(name:"summary", value:"VLC Media Player is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw exists as user-supplied input is not properly sanitized when handling
a specially crafted WAV file.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause a denial of service
conditions or potentially execute arbitrary code.");
  script_tag(name:"affected", value:"VLC media player version 2.1.3 on Mac OS X.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/126564");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_vlc_media_player_detect_macosx.nasl");
  script_mandatory_keys("VLC/Media/Player/MacOSX/Version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

vlcVer = get_app_version(cpe:CPE);
if(!vlcVer){
  exit(0);
}

if(version_is_equal(version:vlcVer, test_version:"2.1.3"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
