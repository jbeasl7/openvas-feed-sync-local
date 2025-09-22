# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900757");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-03-30 16:15:33 +0200 (Tue, 30 Mar 2010)");
  script_cve_id("CVE-2010-1042");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Microsoft Windows Media Player '.AVI' File DOS Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_ms_win_media_player_detect_900173.nasl");
  script_mandatory_keys("Win/MediaPlayer/Ver");

  script_tag(name:"summary", value:"Windows Media Player is prone to a denial of service vulnerability.");

  script_tag(name:"insight", value:"The flaw is due to an error in '.avi' file which fails to perform colorspace
  conversion properly and causes a denial of service (memory corruption).");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause a denial
  of service or possibly execute arbitrary code via a crafted message.");

  script_tag(name:"affected", value:"Microsoft Windows Media Player versions 11.x.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38790");
  script_xref(name:"URL", value:"http://www.security-database.com/detail.php?alert=CVE-2010-1042");

  exit(0);
}

include("version_func.inc");

if(!version = get_kb_item("Win/MediaPlayer/Ver"))
  exit(0);

if(version_in_range(version:version, test_version:"11", test_version2:"11.0.6000.6324")) {
  security_message(port:0, data:"The target host was found to be vulnerable");
  exit(0);
}

exit(99);
