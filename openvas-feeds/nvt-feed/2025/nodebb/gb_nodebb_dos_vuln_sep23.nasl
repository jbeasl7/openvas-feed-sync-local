# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nodebb:nodebb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.171138");
  script_version("2025-01-31T15:39:24+0000");
  script_tag(name:"last_modification", value:"2025-01-31 15:39:24 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"creation_date", value:"2025-01-31 08:03:16 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-02 18:19:47 +0000 (Mon, 02 Oct 2023)");

  script_cve_id("CVE-2023-30591");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("NodeBB < 2.8.11 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("sw_nodebb_http_detect.nasl");
  script_mandatory_keys("nodebb/detected");

  script_tag(name:"summary", value:"NodeBB is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Unauthenticated attackers can trigger a crash, when invoking
  eventName.startsWith() or eventName.toString(), while processing Socket.IO messages via crafted
  Socket.IO messages containing array or object type for the event name respectively.");

  script_tag(name:"affected", value:"NodeBB prior to version 2.8.11.");

  script_tag(name:"solution", value:"Update to version 2.8.11 or later.");

  script_xref(name:"URL", value:"https://starlabs.sg/advisories/23/23-30591/");
  script_xref(name:"URL", value:"https://github.com/NodeBB/NodeBB/commit/830f142b7aea2e597294a84d52c05aab3a3539ca");

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

if (version_is_less(version: version, test_version: "2.8.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.8.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
