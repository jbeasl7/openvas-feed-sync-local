# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:thunderbird_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834830");
  script_version("2025-01-09T06:16:22+0000");
  script_cve_id("CVE-2024-50336");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"creation_date", value:"2024-12-13 11:05:02 +0530 (Fri, 13 Dec 2024)");
  script_name("Mozilla Thunderbird ESR Security Update (MFSA2024-69) - Windows");

  script_tag(name:"summary", value:"Mozilla Thunderbird ESR is prone to an
  insufficient validation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an insufficient
  validation of Matrix Content (MXC) URIs.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to potentially expose clients to path traversal attacks.");

  script_tag(name: "affected" , value:"Mozilla Thunderbird ESR prior to version
  128.5.2 on Windows.");

  script_tag(name: "solution" , value:"Update to version 128.5.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-69/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Thunderbird-ESR/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"128.5.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"128.5.2", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
