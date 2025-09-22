# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:winscp:winscp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814733");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2018-20684");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-15 20:15:00 +0000 (Wed, 15 Jan 2020)");
  script_tag(name:"creation_date", value:"2019-01-17 15:17:22 +0530 (Thu, 17 Jan 2019)");
  script_tag(name:"qod_type", value:"registry");
  script_name("WinSCP Arbitrary File Overwrite Vulnerability - Windows");

  script_tag(name:"summary", value:"WinSCP is prone to an arbitrary file overwrie vulnerability");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"The flaw exists due to missing validation in the
  scp implementation where client would accept arbitrary files sent by the server,
  potentially overwriting unrelated files.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  servers to overwrite arbitrary files on affected system");

  script_tag(name:"affected", value:"WinSCP before version 5.14 beta.");

  script_tag(name:"solution", value:"Update to version 5.14 beta or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://sintonen.fi/advisories/scp-client-multiple-vulnerabilities.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/106526");
  script_xref(name:"URL", value:"https://winscp.net/tracker/1675");
  script_xref(name:"URL", value:"https://github.com/winscp/winscp/commit/49d876f2c5fc00bcedaa986a7cf6dedd6bf16f54");

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_winscp_detect_win.nasl");
  script_mandatory_keys("WinSCP/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"5.14.beta")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"5.14 beta or later", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);