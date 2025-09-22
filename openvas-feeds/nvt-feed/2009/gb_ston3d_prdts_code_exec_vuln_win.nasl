# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800574");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-06-16 15:11:01 +0200 (Tue, 16 Jun 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1792");
  script_name("StoneTrip Ston3D Products Code Execution Vulnerability");
  script_xref(name:"URL", value:"http://www.coresecurity.com/content/StoneTrip-S3DPlayers");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35105");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/503887/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("gb_ston3d_prdts_detect_win.nasl");
  script_mandatory_keys("Ston3D/Standalone_or_Web/Player/Win/Installed");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary
  codes in the context of the application via shell metacharacters in the 'sURL' argument.");

  script_tag(name:"affected", value:"StoneTrip Ston3D Standalone Player version 1.6.2.4 and 1.7.0.1,
  StoneTrip Ston3D Web Player version 1.6.0.0 on Windows.");

  script_tag(name:"insight", value:"The flaw is generated due to inadequate sanitation of user
  supplied data used in the 'system.openURL()' function.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"StoneTrip Ston3D products is prone to a code execution vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("version_func.inc");

wpVer = get_kb_item("Ston3D/Web/Player/Ver");
if((wpVer) && (version_is_equal(version:wpVer, test_version:"1.6.0.0")))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

sapVer = get_kb_item("Ston3D/Standalone/Player/Win/Ver");
if(sapVer){
  if((version_is_equal(version:sapVer, test_version:"1.6.2.4")) ||
     (version_is_equal(version:sapVer, test_version:"1.7.0.1"))){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
