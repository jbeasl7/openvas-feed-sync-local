# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vmware:horizon_view_client";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813822");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2018-6970");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-15 18:33:00 +0000 (Mon, 15 Oct 2018)");
  script_tag(name:"creation_date", value:"2018-08-10 10:11:02 +0530 (Fri, 10 Aug 2018)");
  script_name("VMware Horizon Client Out-of-bounds Read Vulnerability - Windows");

  script_tag(name:"summary", value:"VMware Horizon Client is prone to an out-of-bounds read vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an out-of-bounds read
  error in the Message Framework library.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to obtain sensitive information that may lead to further attacks.");

  script_tag(name:"affected", value:"VMware Horizon Client prior to 4.8.1");

  script_tag(name:"solution", value:"Upgrade to VMware Horizon Client version
  4.8.1 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.vmware.com/security/advisories/VMSA-2018-0019.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/105031");
  script_xref(name:"URL", value:"https://my.vmware.com");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_vmware_horizon_client_detect_win.nasl");
  script_mandatory_keys("VMware/HorizonClient/Win/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vmVer = infos["version"];
vmPath = infos["location"];

if(version_is_less(version:vmVer, test_version:"4.8.1"))
{
  report = report_fixed_ver(installed_version:vmVer, fixed_version:"4.8.1", install_path:vmPath);
  security_message(data:report);
  exit(0);
}
