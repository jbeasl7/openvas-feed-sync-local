# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mcafee:virusscan_enterprise_for_windows";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107159");
  script_version("2024-02-15T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2017-04-27 13:33:12 +0200 (Thu, 27 Apr 2017)");
  script_cve_id("CVE-2016-8030");

  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-08 19:41:00 +0000 (Mon, 08 May 2017)");

  script_tag(name:"qod_type", value:"registry");

  script_name("McAfee VirusScan Enterprise CVE-2016-8030 Memory Corruption Vulnerability - Windows");
  script_tag(name:"summary", value:"McAfee VirusScan Enterprise for Windows is prone to a remote
  memory-corruption vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"A Memory Corruption vulnerability in the Scriptscan COM Object
  in McAfee VirusScan Enterprise 8.8 Patch 8 and earlier allows a remote attacker to create a Denial
  of Service on the active Internet Explorer tab via a crafted HTML link.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to cause a denial-of-service
  condition, denying service to legitimate users.");

  script_tag(name:"affected", value:"VirusScan Enterprise 8.8 Patch 8 and prior are vulnerable");

  script_tag(name:"solution", value:"Update to VirusScan Enterprise 8.8 Patch 9.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98041");
  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");

  script_family("Denial of Service");

  script_dependencies("gb_mcafee_virusscan_enterprise_detect_win.nasl");
  script_mandatory_keys("McAfee/VirusScan/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!Ver = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version: Ver, test_version:"8.8.0.1804"))
{
  report = report_fixed_ver(installed_version:Ver, fixed_version:"8.8 patch 9(8.8.0.1804)");
  security_message(data:report);
  exit(0);
}

exit(99);
