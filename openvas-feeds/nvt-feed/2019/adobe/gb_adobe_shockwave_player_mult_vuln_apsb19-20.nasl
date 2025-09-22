# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:shockwave_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814963");
  script_version("2025-09-16T05:38:45+0000");
  script_cve_id("CVE-2019-7098", "CVE-2019-7099", "CVE-2019-7100", "CVE-2019-7101",
                "CVE-2019-7102", "CVE-2019-7103", "CVE-2019-7104");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-04-11 13:38:50 +0530 (Thu, 11 Apr 2019)");
  script_name("Adobe Shockwave Player Multiple Unspecified Memory Corruption Vulnerabilities (APSB19-20)");

  script_tag(name:"summary", value:"Adobe Shockwave Player is prone to multiple unspecified memory corruption vulnerabilities");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist in Adobe Shockwave
  Player, which could allow for arbitrary code execution.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the user running the
  affected application. Failed exploit attempts will likely result in
  denial-of-service conditions");

  script_tag(name:"affected", value:"Adobe Shockwave Player version before 12.3.5.205 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Shockwave Player version 12.3.5.205
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/shockwave/apsb19-20.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/107822");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_shockwave_player_detect.nasl");
  script_mandatory_keys("Adobe/ShockwavePlayer/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"12.3.5.205")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"12.3.5.205", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
