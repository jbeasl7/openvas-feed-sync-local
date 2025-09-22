# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:foxitsoftware:reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.133026");
  script_version("2025-08-20T05:40:05+0000");
  script_cve_id("CVE-2025-32451");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-08-20 05:40:05 +0000 (Wed, 20 Aug 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-13 14:15:31 +0000 (Wed, 13 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-08-14 08:04:13 +0530 (Thu, 14 Aug 2025)");

  script_name("Foxit Reader Memory Corruption Vulnerability (Aug 2025)");

  script_tag(name:"summary", value:"Foxit Reader is prone to a memory corruption vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"A memory corruption vulnerability exists due to the use of an
  uninitialized pointer. A specially crafted Javascript code inside a malicious PDF document can
  trigger this vulnerability, which can lead to memory corruption and result in arbitrary code
  execution. An attacker needs to trick the user into opening the malicious file to trigger this
  vulnerability. Exploitation is also possible if a user visits a specially crafted, malicious
  site if the browser plugin extension is enabled.");

  script_tag(name:"affected", value:"Foxit Reader version 2025.1.0.27937 and prior.");

  script_tag(name:"solution", value:"Update to version 2025.2.0.33046 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://talosintelligence.com/vulnerability_reports/TALOS-2025-2202");
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_foxit_reader_detect_portable_win.nasl");
  script_mandatory_keys("foxit/reader/ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"2025.1.0.27937")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2025.2.0.33046", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
