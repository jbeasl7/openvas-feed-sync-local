# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803043");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2012-4987");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-11-06 12:38:20 +0530 (Tue, 06 Nov 2012)");
  script_name("RealPlayer Watch Folders Function Buffer Overflow Vulnerability - Windows");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2012/Oct/189");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56324");
  script_xref(name:"URL", value:"http://www.reactionpenetrationtesting.co.uk/realplayer-watchfolders.html");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/117691/Realplayer-Watchfolders-Long-Filepath-Overflow.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_realplayer_detect_win.nasl");
  script_mandatory_keys("RealPlayer/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
arbitrary code on the system.");
  script_tag(name:"affected", value:"RealPlayer version 15.0.5.109");
  script_tag(name:"insight", value:"The 'Watch Folders' function fails to process an overly long
directory path, which can be exploited to cause stack-based buffer overflow via
a crafted ZIP file.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"RealPlayer is prone to a buffer overflow vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

rpVer = get_kb_item("RealPlayer/Win/Ver");
if(!rpVer){
  exit(0);
}

if(version_is_equal(version:rpVer, test_version:"15.0.5.109")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
