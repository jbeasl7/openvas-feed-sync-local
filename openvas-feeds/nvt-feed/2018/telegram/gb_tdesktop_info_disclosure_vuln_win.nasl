# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:telegram:tdesktop";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814310");
  script_version("2025-02-25T13:24:30+0000");
  script_tag(name:"last_modification", value:"2025-02-25 13:24:30 +0000 (Tue, 25 Feb 2025)");
  script_tag(name:"creation_date", value:"2018-11-09 17:30:33 +0530 (Fri, 09 Nov 2018)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-06 20:25:00 +0000 (Thu, 06 Dec 2018)");

  script_cve_id("CVE-2018-17780");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Telegram Desktop 1.3.14 Information Disclosure Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_telegram_desktop_smb_login_detect.nasl");
  script_mandatory_keys("telegram/desktop/detected");

  script_tag(name:"summary", value:"Telegram Desktop is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists because the peer-to-peer connection is not
  private by design, as it directly exposes the IP addresses of the two participants. A mechanism
  to mask users IP addresses when calling each other is not present on Telegram's desktop client");

  script_tag(name:"impact", value:"Successful exploitation will expose a user's IP address when
  making a call.");

  script_tag(name:"affected", value:"Telegram Desktop version 1.3.14.0 on Windows.");

  script_tag(name:"solution", value:"Update to version 1.3.17.0, 1.4.0.0 or later.");

  script_xref(name:"URL", value:"https://www.inputzero.io/2018/09/bug-bounty-telegram-cve-2018-17780.html");
  script_xref(name:"URL", value:"https://desktop.telegram.org/");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_equal(version:version, test_version:"1.3.14.0"))
{
  report = report_fixed_ver(installed_version:version, fixed_version:"1.3.17.0 / 1.4.0.0", install_path:location);
  security_message(data:report);
  exit(0);
}

exit(99);
