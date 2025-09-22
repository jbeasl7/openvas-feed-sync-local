# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:gnu:mailman";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143773");
  script_version("2025-04-25T15:41:53+0000");
  script_tag(name:"last_modification", value:"2025-04-25 15:41:53 +0000 (Fri, 25 Apr 2025)");
  script_tag(name:"creation_date", value:"2020-04-28 04:31:47 +0000 (Tue, 28 Apr 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-27 16:15:00 +0000 (Tue, 27 Oct 2020)");

  script_cve_id("CVE-2020-12137");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Mailman 2.x < 2.1.30 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("mailman_http_detect.nasl");
  script_mandatory_keys("gnu_mailman/detected");

  script_tag(name:"summary", value:"Mailman is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"GNU Mailman uses the .obj extension for scrubbed
  application/octet-stream MIME parts. This behavior may contribute to XSS attacks against
  list-archive visitors, because an HTTP reply from an archive web server may lack a MIME type, and
  a web browser may perform MIME sniffing, conclude that the MIME type should have been text/html,
  and execute JavaScript code.");

  script_tag(name:"affected", value:"GNU Mailman versions 2.0.0 through 2.1.29.");

  script_tag(name:"solution", value:"Update to version 2.1.30 or later.");

  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2020/02/24/2");

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

if (version_in_range(version: version, test_version: "2.0.0", test_version2: "2.1.29")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.1.30", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
