# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:thycotic:secret_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140258");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-07-31 14:35:01 +0700 (Mon, 31 Jul 2017)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Thycotic Secret Server Redirect Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_thycotic_secret_server_detect.nasl");
  script_mandatory_keys("thycotic_secretserver/installed");

  script_tag(name:"summary", value:"The share function in Thycotic Secret Server mishandles the Back Button,
  leading to unintended redirections.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Thycotic Secret Server before version 10.2.000019.");

  script_tag(name:"solution", value:"Update to version 10.2.000019 or later.");

  script_xref(name:"URL", value:"https://thycotic.com/products/secret-server/resources/advisories/thy-ss-009/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "10.2.000019")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.2.000019");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
