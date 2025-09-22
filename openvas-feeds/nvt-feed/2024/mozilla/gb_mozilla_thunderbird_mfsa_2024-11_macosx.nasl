# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832858");
  script_version("2025-01-09T06:16:22+0000");
  script_cve_id("CVE-2024-1936");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"creation_date", value:"2024-03-11 11:51:54 +0530 (Mon, 11 Mar 2024)");
  script_name("Mozilla Thunderbird Security Update (MFSA2024-11) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to an
  information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an encrypted subject
  of an email message could be incorrectly and permanently assigned to an
  arbitrary other email message in Thunderbird's local cache.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to obtain sensitive information.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before
  115.8.1 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to version 115.8.1 or later,
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-11/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Thunderbird/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"115.8.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"115.8.1", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}
