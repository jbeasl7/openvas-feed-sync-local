# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ametys:cms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107257");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-11-13 13:29:03 +0200 (Mon, 13 Nov 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Ametys CMS Unauthenticated Password Reset Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ametys_cms_detect.nasl");
  script_mandatory_keys("ametys/detected");

  script_tag(name:"summary", value:"Ametys CMS is prone to an unauthenticated password reset vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Unauthenticated user can perform administrative operations without properly authorization.");

  script_tag(name:"affected", value:"Ametys CMS prior to 4.0.3");

  script_tag(name:"solution", value:"Update to version 4.0.3 or later.");

  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/3517");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!Port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: Port))
  exit(0);

if (version_is_less(version: version, test_version: "4.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.3");
  security_message(port: Port, data: report);
  exit(0);
}

exit(99);
