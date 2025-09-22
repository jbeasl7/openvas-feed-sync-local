# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:bitvise:winsshd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813384");
  script_version("2024-02-22T14:37:29+0000");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-02-22 14:37:29 +0000 (Thu, 22 Feb 2024)");
  script_tag(name:"creation_date", value:"2018-06-04 13:54:02 +0530 (Mon, 04 Jun 2018)");
  script_name("Bitvise SSH Server 6.x < 6.51, 7.x < 7.41 DoS Vulnerability");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_bitvise_ssh_server_consolidation.nasl");
  script_mandatory_keys("bitvise/ssh_server/detected");

  script_xref(name:"URL", value:"https://www.bitvise.com/flowssh-version-history#security-notification-741");

  script_tag(name:"summary", value:"Bitvise SSH Server is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an invalid memory access error.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to cause the SSH
  Server's main service to stop abruptly and also can cause the SSH Client to stop abruptly.");

  script_tag(name:"affected", value:"Bitvise SSH Server version 6.x prior to 6.51 and 7.x prior to
  7.41.");

  script_tag(name:"solution", value:"Update to version 6.51, 7.41 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "6.0", test_version_up: "6.51") ||
    version_in_range_exclusive(version: version, test_version_lo: "7.0", test_version_up: "7.41")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.51/7.41", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
