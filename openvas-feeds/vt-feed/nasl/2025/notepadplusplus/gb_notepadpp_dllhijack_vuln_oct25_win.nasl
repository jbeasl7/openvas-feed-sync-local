# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:notepad-plus-plus:notepad++";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836694");
  script_version("2026-02-03T05:55:35+0000");
  script_cve_id("CVE-2025-56383");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2026-02-03 05:55:35 +0000 (Tue, 03 Feb 2026)");
  script_tag(name:"creation_date", value:"2025-10-06 12:53:02 +0530 (Mon, 06 Oct 2025)");
  script_name("Notepad++ DLL Hijacking Vulnerability (Oct 2025)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_notepadpp_detect_portable_win.nasl", "gb_notepadpp_detect_win.nasl");
  script_mandatory_keys("Notepad++64/Win/installed");

  script_xref(name:"URL", value:"https://github.com/zer0t0/CVE-2025-56383-Proof-of-Concept");
  script_xref(name:"URL", value:"https://notepad-plus-plus.org/news/v886-released/");
  script_xref(name:"URL", value:"https://github.com/zer0t0/CVE-2025-56383-Proof-of-Concept/issues/1");

  script_tag(name:"summary", value:"Notepad++ is prone to a DLL hijacking vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker to execute malicious
  code.");

  script_tag(name:"affected", value:"Notepad++ version 8.8.3 and prior.");

  script_tag(name:"solution", value:"No solution was made available by the vendor.

  Note: This flaw is disputed by multiple parties because the behavior only occurs when a user
  installs the product into a directory tree that allows write access by arbitrary unprivileged
  users. Please see the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"8.8.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See references", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
