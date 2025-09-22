# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:money";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800218");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2009-01-08 14:06:04 +0100 (Thu, 08 Jan 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2008-5823");
  script_name("Microsoft Money 'prtstb06.dll' Denial of Service vulnerability");
  script_xref(name:"URL", value:"http://jbrownsec.blogspot.com/2008/12/new-year-research-are-upon-us.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_ms_money_detect.nasl");
  script_mandatory_keys("MS/Money/Win/Installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to change the vulnerable
  EIP value and can cause denial of service to the application.");

  script_tag(name:"affected", value:"Microsoft Money 2006.");

  script_tag(name:"insight", value:"The flaw is due to an error in the Windows Based Script Host which lets
  the attacker execute arbitrary codes in the vulnerable buffer to crash
  the application.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Microsoft Money is prone to a denial
  of service vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if( vers =~ "^2006" ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"None", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
