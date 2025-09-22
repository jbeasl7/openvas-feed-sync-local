# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:open-xchange:open-xchange_appsuite";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809847");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2016-4046", "CVE-2016-4045", "CVE-2016-4026");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-19 15:46:00 +0000 (Fri, 19 Oct 2018)");
  script_tag(name:"creation_date", value:"2017-01-02 13:59:09 +0530 (Mon, 02 Jan 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Open-Xchange (OX) App Suite Multiple Vulnerabilities -02 (Jan 2017)");

  script_tag(name:"summary", value:"Open-Xchange (OX) App Suite is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - An improper validation of input passed to API calls.

  - An improper validation of input passed RSS reader of App Suite.

  - The content sanitizer component has an issue with filtering malicious content
    in case invalid HTML code is provided.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary script code in the browser of an unsuspecting user in the
  context of the affected application. This may let the attacker steal cookie-based
  authentication credentials and bypass certain security restrictions to perform
  unauthorized actions, insert and display spoofed content, which may aid in
  further attacks.");

  script_tag(name:"affected", value:"Open-Xchange (OX) App Suite versions
  7.6.2-rev0 - 7.6.2-rev53,
  7.6.3-rev0 - 7.6.3-rev10,
  7.8.0-rev0 - 7.8.0-rev29,
  7.8.1-rev0 - 7.8.1-rev10");

  script_tag(name:"solution", value:"Update to version 7.6.2-rev54, or 7.6.3-rev11, or 7.8.0-rev30, or 7.8.1-rev11, or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/538732/100/0/threaded");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91359");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91356");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91357");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_open-xchange_ox_app_suite_http_detect.nasl");
  script_mandatory_keys("open-xchange/app_suite/detected");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!revision = get_kb_item("open-xchange/app_suite/" + port + "/revision"))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];
version += "." + revision;

if(version =~ "^7\.8\.0" && version_is_less(version: version, test_version: "7.8.0.30"))
  fix = "7.8.0-rev30";

else if(version =~ "^7\.8\.1" && version_is_less(version: version, test_version: "7.8.1.11"))
  fix = "7.8.1-rev11";

else if(version =~ "^7\.6\.2" && version_is_less(version: version, test_version: "7.6.2.54"))
  fix = "7.6.2-rev54";

else if(version =~ "^7\.6\.3" && version_is_less(version: version, test_version: "7.6.3.11"))
  fix = "7.6.3-rev11";

if (fix) {
  report = report_fixed_ver(installed_version: version, fixed_version: fix, install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
