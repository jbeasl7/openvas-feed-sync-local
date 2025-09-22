# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800576");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-06-16 15:11:01 +0200 (Tue, 16 Jun 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1792");
  script_name("StoneTrip Ston3D Standalone Player Code Execution Vulnerability - Linux");
  script_xref(name:"URL", value:"http://www.coresecurity.com/content/StoneTrip-S3DPlayers");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35105");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/503887/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("gb_ston3d_prdts_detect_lin.nasl");
  script_mandatory_keys("Ston3D/Standalone/Player/Lin/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary
codes in the context of the application via shell metacharacters in the 'sURL'
argument.");
  script_tag(name:"affected", value:"StoneTrip Ston3D Standalone Player version 1.6.2.4 and prior.");
  script_tag(name:"insight", value:"The flaw is generated due to inadequate sanitation of user
supplied data used in the 'system.openURL()' function.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"StoneTrip Ston3D Standalone Player is prone to a code execution vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"executable_version");
  exit(0);
}

include("version_func.inc");

sapVer = get_kb_item("Ston3D/Standalone/Player/Lin/Ver");
if(!sapVer){
  exit(0);
}

if(version_is_less_equal(version:sapVer, test_version:"1.6.2.4")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
