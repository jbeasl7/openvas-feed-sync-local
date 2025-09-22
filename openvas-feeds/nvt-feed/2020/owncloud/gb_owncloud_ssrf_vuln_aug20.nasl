# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:owncloud:owncloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144860");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2020-10-29 04:40:57 +0000 (Thu, 29 Oct 2020)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-25 20:45:00 +0000 (Thu, 25 Feb 2021)");

  script_cve_id("CVE-2020-10252");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ownCloud < 10.3.2 SSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_http_detect.nasl");
  script_mandatory_keys("owncloud/detected");

  script_tag(name:"summary", value:"ownCloud is prone to a server-side request forgery (SSRF)
  vulnerability in the 'Add to your ownCloud' functionality.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"It is possible to force the ownCloud server to execute GET requests against a
  crafted URL on the internal or external network (Server Side Request Forgery) after receiving a public
  link-share URL. The criticality of this issue is lowered because the attacker can not see the result of the
  forged request thus there is no possibility to exfiltrate any data from an internal resource.");

  script_tag(name:"impact", value:"An authenticated attacker can interact with local services blindly (aka Blind SSRF)
  or conduct a Denial Of Service attack.");

  script_tag(name:"affected", value:"ownCloud version 10.3.1 and prior.");

  script_tag(name:"solution", value:"Update to version 10.3.2 or later.");

  script_xref(name:"URL", value:"https://owncloud.com/security-advisories/ssrf-in-add-to-your-owncloud-functionality/");

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

if (version_is_less(version: version, test_version: "10.3.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.3.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
