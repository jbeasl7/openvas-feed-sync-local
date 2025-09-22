# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tigris:tortoisesvn";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801290");
  script_version("2025-09-16T05:38:45+0000");
  script_cve_id("CVE-2010-3199");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"creation_date", value:"2010-09-21 16:43:08 +0200 (Tue, 21 Sep 2010)");
  script_name("TortoiseSVN Insecure Library Loading Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gb_tortoise_svn_detect.nasl");
  script_mandatory_keys("tortoisesvn/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/513442/100/0/threaded");
  script_xref(name:"URL", value:"http://tortoisesvn.tigris.org/ds/viewMessage.do?dsForumId=4061&dsMessageId=2653163");
  script_xref(name:"URL", value:"http://tortoisesvn.tigris.org/ds/viewMessage.do?dsForumId=4061&dsMessageId=2653202&orderBy=createDate&orderType=desc");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute
  arbitrary code and conduct DLL hijacking attacks.");

  script_tag(name:"affected", value:"TortoiseSVN 1.6.10, Build 19898 and prior.");

  script_tag(name:"insight", value:"The flaw is due to the application insecurely loading certain
  libraries from the current working directory, which could allow attackers to execute arbitrary
  code by tricking a user into opening a file from a network share.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"TortoiseSVN is prone to insecure library loading vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less_equal( version:vers, test_version:"1.6.10" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"None", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
