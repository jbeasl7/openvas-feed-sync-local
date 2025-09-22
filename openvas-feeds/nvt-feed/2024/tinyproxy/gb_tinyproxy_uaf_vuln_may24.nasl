# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:banu:tinyproxy";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127770");
  script_version("2024-12-06T15:41:14+0000");
  script_tag(name:"last_modification", value:"2024-12-06 15:41:14 +0000 (Fri, 06 Dec 2024)");
  script_tag(name:"creation_date", value:"2024-06-06 10:31:40 +0700 (Thu, 06 Jun 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-05-01 16:15:07 +0000 (Wed, 01 May 2024)");

  script_cve_id("CVE-2023-49606");

  # nb: Backports on at least Debian, Fedora and openSUSE exists...
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tinyproxy <= 1.11.1 UAF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_tinyproxy_http_detect.nasl");
  script_mandatory_keys("tinyproxy/detected");

  script_tag(name:"summary", value:"Tinyproxy is prone to an use-after-free (UAF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A specially crafted HTTP header can trigger reuse of previously
  freed memory, which leads to memory corruption and could lead to remote code execution.");

  script_tag(name:"affected", value:"Tinyproxy version 1.11.1 and prior.");

  script_tag(name:"solution", value:"Update to version 1.11.2 or later.");

  script_xref(name:"URL", value:"https://github.com/tinyproxy/tinyproxy/releases/tag/1.11.2");
  script_xref(name:"URL", value:"https://github.com/tinyproxy/tinyproxy/issues/533");
  script_xref(name:"URL", value:"https://talosintelligence.com/vulnerability_reports/TALOS-2023-1889");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "1.11.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.11.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
