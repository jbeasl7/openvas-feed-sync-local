# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:measuresoft:scadapro_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803949");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2012-1824");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-10-03 12:30:46 +0530 (Thu, 03 Oct 2013)");
  script_name("Measuresoft ScadaPro Server DLL Code Execution Vulnerability");


  script_tag(name:"summary", value:"Measuresoft ScadaPro Server is prone to a code execution vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to version 4.0.0 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"insight", value:"A flaw exists in the application, which does not directly specify the fully
qualified path to a dynamic-linked library.");
  script_tag(name:"affected", value:"Measuresoft ScadaPro Server before 4.0.0");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code on the
system via a specially-crafted library.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/75860");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53681");
  script_xref(name:"URL", value:"http://www.us-cert.gov/control_systems/pdf/ICSA-12-145-01.pdf");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("gb_measuresoft_scadapro_server_detect.nasl");
  script_mandatory_keys("ScadaProServer/Win/Ver");
  script_xref(name:"URL", value:"http://www.measuresoft.com/download/current_release.aspx");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!scadaprosvrVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:scadaprosvrVer, test_version:"4.0.0"))
{
  report = report_fixed_ver(installed_version:scadaprosvrVer, fixed_version:"4.0.0");
  security_message(port: 0, data: report);
  exit(0);
}
