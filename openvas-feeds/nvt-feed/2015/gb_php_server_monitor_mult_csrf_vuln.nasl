# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpserver:monitor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806528");
  script_version("2024-03-04T14:37:58+0000");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2015-11-02 18:23:47 +0530 (Mon, 02 Nov 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("PHP Server Monitor Multiple CSRF Vulnerabilities");

  script_tag(name:"summary", value:"PHP Server Monitor is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple CSRF
  issues in the application.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to add arbitrary users & servers to the system, modify system
  configurations and delete arbitrary servers.");

  script_tag(name:"affected", value:"PHP Server Monitor 3.1.1");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/134144");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/134143");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_php_server_monitor_detect.nasl");
  script_mandatory_keys("PHP/Server/Monitor/Installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_equal(version:version, test_version:"3.1.1")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"WillNotFix");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
