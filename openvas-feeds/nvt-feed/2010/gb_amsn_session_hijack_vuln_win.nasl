# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902045");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-04-29 10:04:32 +0200 (Thu, 29 Apr 2010)");
  script_cve_id("CVE-2008-7255");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_name("aMSN < 0.97.1 Session Hijack Vulnerability - Windows");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/393176.php");
  script_xref(name:"URL", value:"http://www.amsn-project.net/forums/index.php?topic=5317.0");
  script_xref(name:"URL", value:"http://sourceforge.net/project/shownotes.php?release_id=610067");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_amsn_detect_win.nasl");
  script_mandatory_keys("aMSN/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to hijack a session by visiting
  an unattended workstation.");
  script_tag(name:"affected", value:"aMSN prior to version 0.97.1");
  script_tag(name:"insight", value:"The flaw is due to an error in 'login_screen.tcl' which saves a
  password after logout. This allows attackers to hijack the session.");
  script_tag(name:"solution", value:"Update to version 0.97.1 or later.");
  script_tag(name:"summary", value:"aMSN is prone to a session hijacking vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

amsnVer = get_kb_item("aMSN/Win/Ver");

if(amsnVer != NULL)
{
  if(version_is_less(version:amsnVer, test_version:"0.97.1")){
    report = report_fixed_ver(installed_version:amsnVer, fixed_version:"0.97.1");
    security_message(port: 0, data: report);
  }
}
