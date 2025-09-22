# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:robohelp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803771");
  script_version("2023-11-24T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-11-24 05:05:36 +0000 (Fri, 24 Nov 2023)");
  script_tag(name:"creation_date", value:"2013-10-17 16:38:27 +0530 (Thu, 17 Oct 2013)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2013-5327");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Adobe RoboHelp Arbitrary Code Execution Vulnerability (APSB13-24)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_robohelp_nd_robohelp_server_smb_login_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("adobe/robohelp/smb-login/detected", "adobe/robohelp/smb-login/installpath");

  script_tag(name:"summary", value:"Adobe RoboHelp is prone to an arbitrary code execution
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified error and can be exploited to
  cause memory corruption.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary
  code, cause a denial of service (application crash).");

  script_tag(name:"affected", value:"Adobe RoboHelp version 10.x.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54647");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62887");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/robohelp/apsb13-24.html");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

if (!vers = get_app_version(cpe:CPE))
  exit(0);

if (vers !~ "^10\.")
  exit(0);

dllPath = get_kb_item("adobe/robohelp/smb-login/installpath");
if (!dllPath || "Could not find the install location" >< dllPath)
  exit(0);

file = "\RoboHTML\MDBMS.dll";
if (!dllVer = fetch_file_version(sysPath:dllPath, file_name:file))
  exit(0);

if (version_in_range(version: dllVer, test_version: "10.0", test_version2: "10.0.1.293")) {
  report = report_fixed_ver(installed_version: dllVer, fixed_version: "See advisory", file_checked: dllPath + file);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
