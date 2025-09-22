# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814046");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2018-12385");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-06 19:03:00 +0000 (Thu, 06 Dec 2018)");
  script_tag(name:"creation_date", value:"2018-09-25 11:40:16 +0530 (Tue, 25 Sep 2018)");
  script_name("Mozilla Firefox Security Advisories (MFSA2018-22, MFSA2018-23) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to data stored in the
  local cache in the user profile directory.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to write data into the local cache or from locally installed malware. This issue
  also triggers a non-exploitable startup crash for users.");

  script_tag(name:"affected", value:"Mozilla Firefox version before 62.0.2 on
  Windows.");

  script_tag(name:"solution", value:"Update to Mozilla Firefox version 62.0.2
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-22");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl", "gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"62.0.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"62.0.2", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
