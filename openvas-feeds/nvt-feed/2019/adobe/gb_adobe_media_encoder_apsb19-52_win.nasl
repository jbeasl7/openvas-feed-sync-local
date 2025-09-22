# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:media_encoder";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815666");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2019-8241", "CVE-2019-8242", "CVE-2019-8243", "CVE-2019-8244",
                "CVE-2019-8246");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-21 19:39:00 +0000 (Thu, 21 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-11-14 12:23:49 +0530 (Thu, 14 Nov 2019)");
  script_name("Adobe Media Encoder Security Updates (APSB19-52) - Windows");

  script_tag(name:"summary", value:"Adobe Media Encoder is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple read
  and write out-of-bounds error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code and gain access to sensitive information.");

  script_tag(name:"affected", value:"Adobe Media Encoder 13.1 and earlier versions");

  script_tag(name:"solution", value:"Upgrade to Adobe Media Encoder 14 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/media-encoder/apsb19-52.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_media_encoder_detect_win.nasl");
  script_mandatory_keys("adobe/mediaencoder/win/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
ad_ver = infos["version"];
ad_path = infos["location"];

if(version_is_less(version:ad_ver, test_version:"14.0"))
{
  report = report_fixed_ver(installed_version:ad_ver, fixed_version:"14.0", install_path:ad_path);
  security_message(data:report);
  exit(0);
}
exit(99);
