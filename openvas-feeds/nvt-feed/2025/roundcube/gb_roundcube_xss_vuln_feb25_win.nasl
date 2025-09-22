# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:roundcube:webmail";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153929");
  script_version("2025-02-18T05:38:27+0000");
  script_tag(name:"last_modification", value:"2025-02-18 05:38:27 +0000 (Tue, 18 Feb 2025)");
  script_tag(name:"creation_date", value:"2025-02-04 02:52:58 +0000 (Tue, 04 Feb 2025)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");

  script_cve_id("CVE-2024-57004");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Roundcube Webmail <= 1.6.9 XSS Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_roundcube_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("roundcube/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Roundcube Webmail is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"XSS allows remote authenticated users to upload a malicious
  file as an email attachment, leading to the triggering of the XSS by visiting the SENT
  session.");

  script_tag(name:"affected", value:"Roundcube Webmail version 1.6.9 and probably prior.");

  script_tag(name:"solution", value:"No known solution is available as of 17th February, 2025.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/riya98241/CVE/blob/main/CVE-2024-57004");
  script_xref(name:"URL", value:"https://github.com/roundcube/roundcubemail/issues/9767");

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

if (version_is_less_equal(version: version, test_version: "1.6.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
