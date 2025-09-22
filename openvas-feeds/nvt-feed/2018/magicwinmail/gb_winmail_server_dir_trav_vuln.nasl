# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:magicwinmail:winmail_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141491");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2018-09-19 15:07:23 +0700 (Wed, 19 Sep 2018)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-05 14:26:00 +0000 (Mon, 05 Feb 2018)");

  script_cve_id("CVE-2018-5700");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Winmail Server < 6.3 Directory Traversal Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_winmail_server_web_detect.nasl");
  script_mandatory_keys("winmail_server/detected");

  script_tag(name:"summary", value:"Winmail Server allows remote code execution (RCE) by
  authenticated users who leverage directory traversal in a netdisk.php copy_folder_file call (in
  inc/class.ftpfolder.php) to move a .php file from the FTP folder into a web folder.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Winmail Server 6.2 and prior.");

  script_tag(name:"solution", value:"Update to version 6.3 or later.");

  script_xref(name:"URL", value:"https://github.com/0xWfox/Winmail/blob/master/Winmail_6.2.md");
  script_xref(name:"URL", value:"http://www.magicwinmail.net/changelog.asp");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "6.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
