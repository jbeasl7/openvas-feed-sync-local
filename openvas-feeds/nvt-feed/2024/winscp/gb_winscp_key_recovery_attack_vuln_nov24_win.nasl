# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:winscp:winscp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834767");
  script_version("2024-11-26T07:35:52+0000");
  script_cve_id("CVE-2024-31497");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-11-26 07:35:52 +0000 (Tue, 26 Nov 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-05-10 14:33:55 +0000 (Fri, 10 May 2024)");
  script_tag(name:"creation_date", value:"2024-11-20 16:27:40 +0530 (Wed, 20 Nov 2024)");
  script_name("WinSCP Key Recovery Attack Vulnerability - Windows");

  script_tag(name:"summary", value:"WinSCP is prone to a key recovery attack
  vulnerability");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a key recovery
  attack vulnerability in WinSCP.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to compromise a victim's private key and conduct supply-chain attacks.");

  script_tag(name:"affected", value:"WinSCP prior to version 6.3.3 on
  Windows.");

  script_tag(name:"solution", value:"Update to version 6.3.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://winscp.net/eng/news.php");
  script_xref(name:"URL", value:"https://winscp.net/eng/docs/history");
  script_copyright("Copyright (C) 2024 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"6.3.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"6.3.3", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);