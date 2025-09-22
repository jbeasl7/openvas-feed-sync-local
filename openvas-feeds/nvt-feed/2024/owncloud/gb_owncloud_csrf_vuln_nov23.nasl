# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:owncloud:owncloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127812");
  script_version("2024-10-08T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-10-08 05:05:46 +0000 (Tue, 08 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-10-07 09:23:51 +0000 (Mon, 07 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:N");

  script_cve_id("CVE-2023-7273");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ownCloud < 10.13.0 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_http_detect.nasl");
  script_mandatory_keys("owncloud/detected");

  script_tag(name:"summary", value:"ownCloud is prone to a cross-site request forgery (CSRF)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"If request has no authorization header, it is created with an
  empty string as value by a rewrite rule. The CSRF check is done by comparing the header value to
  null, meaning that the existing CSRF check is bypassed in this case. An attacker can, for
  example, create a new administrator account if the request is executed in the browser of an
  authenticated victim.");

  script_tag(name:"affected", value:"ownCloud prior to version 10.13.0.");

  script_tag(name:"solution", value:"Update to version 10.13.0 or later.");

  script_xref(name:"URL", value:"https://hackerone.com/reports/2041007");

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

if (version_is_less(version:version, test_version:"10.13.0")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"10.13.0", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
