# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:shockwave_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811210");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2017-3086");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-21 01:29:00 +0000 (Thu, 21 Sep 2017)");
  script_tag(name:"creation_date", value:"2017-06-19 11:33:41 +0530 (Mon, 19 Jun 2017)");
  script_name("Adobe Shockwave Player Memory Corruption Vulnerability (APSB17-18)");

  script_tag(name:"summary", value:"Adobe Shockwave Player is prone to a memory corruption vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to some unspecified memory
  corruption error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain control of the affected system. Depending on the privileges
  associated with this application, an attacker could then install programs. View,
  change, or delete data, or create new accounts with full user rights.");

  script_tag(name:"affected", value:"Adobe Shockwave Player version before
  12.2.9.199 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Shockwave Player version
  12.2.9.199 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/shockwave/apsb17-08.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99019");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_shockwave_player_detect.nasl");
  script_mandatory_keys("Adobe/ShockwavePlayer/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less(version:vers, test_version:"12.2.9.199")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"12.2.9.199");
  security_message(data:report);
  exit(0);
}
