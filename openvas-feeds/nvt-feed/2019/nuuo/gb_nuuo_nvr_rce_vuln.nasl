# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nuuo:nuuo";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140095");
  script_version("2025-02-27T08:17:42+0000");
  script_tag(name:"last_modification", value:"2025-02-27 08:17:42 +0000 (Thu, 27 Feb 2025)");
  script_tag(name:"creation_date", value:"2019-06-07 01:49:23 +0000 (Fri, 07 Jun 2019)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_cve_id("CVE-2019-9653");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("NUUO NVR 1.7.x - 3.3.x RCE Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nuuo_devices_http_detect.nasl");
  script_mandatory_keys("nuuo/device/detected");

  script_tag(name:"summary", value:"NUUO Network Video Recorder (NVR) is prone to an
  unauthenticated remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"NUUO Network Video Recorder allows unauthenticated attackers to
  execute arbitrary commands via shell metacharacters to handle_load_config.php.");

  script_tag(name:"solution", value:"Update to the latest firmware version (e.g. 3.10.x or
  higher).");

  script_xref(name:"URL", value:"https://github.com/grayoneday/CVE-2019-9653");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_greater_equal(version: version, test_version: "1.7") &&
    version_is_less(version: version, test_version: "3.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
