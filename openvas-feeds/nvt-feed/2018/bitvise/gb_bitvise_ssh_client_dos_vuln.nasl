# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:bitvise:ssh_client";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813386");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2018-06-04 13:54:02 +0530 (Mon, 04 Jun 2018)");
  script_name("Bitvise SSH Client Denial of Service Vulnerability");

  script_tag(name:"summary", value:"Bitvise SSH Client Suite is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an invalid memory access
  error.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to cause the target client to stop processing.");

  script_tag(name:"affected", value:"Bitvise SSH Client 6.xx and 7.xx
  before 7.41.");

  script_tag(name:"solution", value:"Upgrade to version 7.41 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.bitvise.com/flowssh-version-history#security-notification-741");

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_bitvise_ssh_client_detect.nasl");
  script_mandatory_keys("BitviseSSH/Client/Win/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^[67]\." && version_is_less(version:vers, test_version:"7.41.0.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.41", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
