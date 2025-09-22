# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:symantec:web_gateway";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106342");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-10-07 10:41:48 +0700 (Fri, 07 Oct 2016)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-20 13:31:00 +0000 (Thu, 20 Apr 2017)");

  script_cve_id("CVE-2016-5313");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Symantec Web Gateway OS Command Injection Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_symantec_web_gateway_detect.nasl");
  script_mandatory_keys("symantec_web_gateway/installed");

  script_tag(name:"summary", value:"Symantec Web Gateway is prone to a OS command injection vulnerability.");

  script_tag(name:"insight", value:"The vulnerable code is located in the /spywall/new_whitelist.php script.
The vulnerability exists because the validation checks may be bypassed by setting the 'sid' POST parameter to a
value different from zero. In this way, even though the 'white_ip' POST parameter is not a valid domain or IP
address, it will be passed to the add_whitelist() function as its $url parameter.");

  script_tag(name:"impact", value:"An authenticated attacker may execute arbitrary OS commands with the
privileges of the root user of the appliance.");

  script_tag(name:"affected", value:"Symantec Web Gateway version 5.2.2 and prior.");

  script_tag(name:"solution", value:"Update to version 5.2.5 or later.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "5.2.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.5");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
