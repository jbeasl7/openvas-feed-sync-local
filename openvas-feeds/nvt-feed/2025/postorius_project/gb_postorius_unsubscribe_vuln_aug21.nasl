# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:postorius_project:postorius";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154377");
  script_version("2025-04-25T15:41:53+0000");
  script_tag(name:"last_modification", value:"2025-04-25 15:41:53 +0000 (Fri, 25 Apr 2025)");
  script_tag(name:"creation_date", value:"2025-04-25 07:48:53 +0000 (Fri, 25 Apr 2025)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-24 03:04:23 +0000 (Fri, 24 Sep 2021)");

  script_cve_id("CVE-2021-40347");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Postorius < 1.3.5 Unsubscribe Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_postorius_http_detect.nasl");
  script_mandatory_keys("postorius/detected");

  script_tag(name:"summary", value:"Postorius is prone to an unsubscribe vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An attacker (logged into any account) can send a crafted POST
  request to unsubscribe any user from a mailing list, also revealing whether that address was
  subscribed in the first place.");

  script_tag(name:"affected", value:"Postorius prior to version 1.3.5.");

  script_tag(name:"solution", value:"Update to version 1.3.5 or later.");

  script_xref(name:"URL", value:"https://gitlab.com/mailman/postorius/-/issues/531");

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

if (version_is_less(version: version, test_version: "1.3.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.3.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
