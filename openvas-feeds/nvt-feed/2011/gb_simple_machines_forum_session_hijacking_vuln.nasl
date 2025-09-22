# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:simplemachines:smf";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802334");
  script_version("2025-07-22T05:43:35+0000");
  script_tag(name:"last_modification", value:"2025-07-22 05:43:35 +0000 (Tue, 22 Jul 2025)");
  script_tag(name:"creation_date", value:"2011-09-16 17:22:17 +0200 (Fri, 16 Sep 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Simple Machines Forum (SMF) 2.0 Session Hijacking Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_simple_machines_forum_http_detect.nasl");
  script_mandatory_keys("smf/detected");

  script_tag(name:"summary", value:"Simple Machines Forum (SMF) is prone to session hijacking
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to improper handling of user's sessions,
  allowing a remote attacker to hijack a valid user's session via a specially crafted link.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to obtain sensitive
  information such as user's session credentials and may aid in further attacks.");

  script_tag(name:"affected", value:"SMF version 2.0 is known to be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/17637");
  script_xref(name:"URL", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/69056");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121214428/http://www.securityfocus.com/bid/49078");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_equal(version: version, test_version: "2.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
