# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:remote_desktop_connection";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826961");
  script_version("2024-02-27T05:06:31+0000");
  script_cve_id("CVE-2023-28267");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-27 05:06:31 +0000 (Tue, 27 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-11 21:15:00 +0000 (Tue, 11 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-12 11:14:20 +0530 (Wed, 12 Apr 2023)");
  script_name("Remote Desktop Client Information Disclosure Vulnerability (Apr 2023) - Windows");

  script_tag(name:"summary", value:"Remote Desktop Client is prone to an information
  disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an information disclosure
  vulnerability in Remote Desktop Client.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to disclose information on an affected system.");

  script_tag(name:"affected", value:"Remote Desktop Client prior to public
  version 1.2.4157 on Windows");

  script_tag(name:"solution", value:"Update Remote Desktop Client to public
  version 1.2.4157 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/azure/virtual-desktop/whats-new-client-windows#updates-for-version-124155");

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_remote_desktop_client_detect_win.nasl");
  script_mandatory_keys("remote/desktop/client/win/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version:version, test_version:"1.2.4157")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"1.2.4157", install_path:location);
  security_message(data: report);
  exit(0);
}

exit(99);
