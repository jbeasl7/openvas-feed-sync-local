# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834477");
  script_version("2025-03-14T05:38:04+0000");
  script_cve_id("CVE-2024-8381", "CVE-2024-8382", "CVE-2024-8384");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-14 05:38:04 +0000 (Fri, 14 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-04 15:50:28 +0000 (Wed, 04 Sep 2024)");
  script_tag(name:"creation_date", value:"2025-03-13 14:21:20 +0530 (Thu, 13 Mar 2025)");
  script_name("Mozilla Thunderbird Security Update (mfsa_2024-44) - Windows");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name: "insight" , value:"These vulnerabilities exist:

  - CVE-2024-8381: Type confusion when looking up a property name in a 'with' block

  - CVE-2024-8382: Internal event interfaces were exposed to web content when browser EventHandler listener callbacks ran

  - CVE-2024-8384: Garbage collection could mis-color cross-compartment objects in OOM conditions");

  script_tag(name: "impact" , value:"Successful exploitation allows an attacker
  to run arbitrary code and conduct denial of service attacks.");

  script_tag(name: "affected" , value:"Mozilla Thunderbird prior to version
  115.15 on Windows.");

  script_tag(name: "solution" , value:"Update to version 115.15 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-44/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"115.15")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"115.15", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
