# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814429");
  script_version("2024-02-12T14:37:47+0000");
  script_cve_id("CVE-2018-12393");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-02-12 14:37:47 +0000 (Mon, 12 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-11-02 12:15:23 +0530 (Fri, 02 Nov 2018)");
  script_name("Mozilla Thunderbird Integer Overflow Vulnerability (MFSA2018-26, MFSA2018-28) - Windows");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to an integer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an integer overflow during
  the conversion of scripts to an internal UTF-16 representation.");

  script_tag(name:"impact", value:"Successful exploitation will lead to a
  possible out-of-bounds write.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before
  60.3 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 60.3
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-28/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");
  script_exclude_keys("Thunderbird64/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"60.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"60.3", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
