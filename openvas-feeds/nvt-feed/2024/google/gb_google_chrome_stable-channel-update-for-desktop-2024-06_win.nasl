# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834049");
  script_version("2024-06-21T05:05:42+0000");
  script_cve_id("CVE-2024-5830", "CVE-2024-5831", "CVE-2024-5832", "CVE-2024-5833",
                "CVE-2024-5834", "CVE-2024-5835", "CVE-2024-5836", "CVE-2024-5837",
                "CVE-2024-5838", "CVE-2024-5839", "CVE-2024-5840", "CVE-2024-5841",
                "CVE-2024-5842", "CVE-2024-5843", "CVE-2024-5844", "CVE-2024-5845",
                "CVE-2024-5846", "CVE-2024-5847");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-21 05:05:42 +0000 (Fri, 21 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-20 13:05:43 +0000 (Thu, 20 Jun 2024)");
  script_tag(name:"creation_date", value:"2024-06-13 06:21:01 +0530 (Thu, 13 Jun 2024)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop-2024-06) - Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-5830: Type Confusion in V8

  - CVE-2024-5831: Use after free in Dawn

  Please see the references for more information on the vulnerabilities.");

  script_tag(name: "impact" , value:"Successful exploitation allows an attacker
  to run arbitrary code, conduct spoofing and cause a denial of service
  attacks.");

  script_tag(name: "affected" , value:"Google Chrome prior to version
  126.0.6478.56 on Windows");

  script_tag(name: "solution", value:"Update to version 126.0.6478.56/57 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/06/stable-channel-update-for-desktop.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"126.0.6478.56")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"126.0.6478.56/57", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
