# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:connect";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818503");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2021-08-13 00:05:37 +0530 (Fri, 13 Aug 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-21 20:15:08 +0000 (Thu, 21 Oct 2021)");

  script_cve_id("CVE-2021-36061", "CVE-2021-36062", "CVE-2021-36063", "CVE-2021-40719",
                "CVE-2021-40721");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Adobe Connect Multiple Vulnerabilities (APSB21-66, APSB21-91)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_adobe_connect_http_detect.nasl");
  script_mandatory_keys("adobe/connect/detected");

  script_tag(name:"summary", value:"Adobe Connect is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple input validation errors and
  violation of secure design principles in Adobe Connect software.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute
  arbitrary code and bypass security restrictions.");

  script_tag(name:"affected", value:"Adobe Connect version 11.2.2 and prior.");

  script_tag(name:"solution", value:"Update to version 11.2.3 or later.");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/connect/apsb21-66.html");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/connect/apsb21-91.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "11.2.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.2.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
