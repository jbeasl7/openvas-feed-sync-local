# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107384");
  script_version("2024-02-28T05:05:37+0000");
  script_cve_id("CVE-2013-3249");
  script_tag(name:"last_modification", value:"2024-02-28 05:05:37 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"creation_date", value:"2018-11-27 11:41:33 +0100 (Tue, 27 Nov 2018)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("DameWare Remote Support Buffer Overflow Vulnerability (CVE-2013-3249) - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_dameware_remote_support_detect_win.nasl");
  script_mandatory_keys("dameware/remote_support/win/detected");

  script_tag(name:"summary", value:"DameWare Remote Support is prone to a local buffer overflow vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"DameWare Remote Support is vulnerable to a stack-based buffer overflow, caused by
  improper bounds checking by the DWExporter.exe when importing data");
  script_tag(name:"impact", value:"By persuading a victim to open a specially-crafted Web site, a remote attacker could
  exploit this vulnerability using the 'Add from text file' feature to overflow a buffer and execute arbitrary code on the system or cause the application to crash.");
  script_tag(name:"affected", value:"DameWare Remote Support versions 9.0.1.247, 10.0.0.372 and earlier.");
  script_tag(name:"solution", value:"Updates are available. Please contact the vendor for more information.");

  script_xref(name:"URL", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/85973");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61453");

  exit(0);
}

CPE = "cpe:/a:dameware:remote_support";

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) {
  exit (0);
}

vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"9.0.1.247")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See advisory", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

if(version_in_range(version:vers, test_version:"10.0.0.0", test_version2:"10.0.0.372")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See advisory", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
