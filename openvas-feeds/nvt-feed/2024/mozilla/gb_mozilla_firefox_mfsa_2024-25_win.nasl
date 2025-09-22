# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834054");
  script_version("2024-09-16T05:05:46+0000");
  script_cve_id("CVE-2024-5688", "CVE-2024-5689", "CVE-2024-5690", "CVE-2024-5691",
                "CVE-2024-5692", "CVE-2024-5693", "CVE-2024-5694", "CVE-2024-5695",
                "CVE-2024-5696", "CVE-2024-5697", "CVE-2024-5698", "CVE-2024-5699",
                "CVE-2024-5700", "CVE-2024-5701");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-09-16 05:05:46 +0000 (Mon, 16 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-13 18:31:42 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-06-13 10:37:25 +0530 (Thu, 13 Jun 2024)");
  script_name("Mozilla Firefox Security Update (mfsa_2024-23_2024-26) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-5688: Use-after-free in JavaScript object transplant.

  - CVE-2024-5689: User confusion and possible phishing vector via Firefox Screenshots.

  Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to run arbitrary code, bypass security restrictions, disclose information and
  cause denial of service attacks.");

  script_tag(name:"affected", value:"Mozilla Firefox prior to version 127.");

  script_tag(name:"solution", value:"Update to version 127 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-25/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"127")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"127", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
