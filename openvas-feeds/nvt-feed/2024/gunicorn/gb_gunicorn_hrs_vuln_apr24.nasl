# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:gunicorn:gunicorn";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127727");
  script_version("2024-04-19T15:38:40+0000");
  script_tag(name:"last_modification", value:"2024-04-19 15:38:40 +0000 (Fri, 19 Apr 2024)");
  script_tag(name:"creation_date", value:"2024-04-18 08:31:56 +0000 (Thu, 18 Apr 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");

  script_cve_id("CVE-2024-1135");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Gunicorn < 22.0.0 HTTP Request Smuggling Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_gunicorn_http_detect.nasl");
  script_mandatory_keys("gunicorn/detected");

  script_tag(name:"summary", value:"Gunicorn is prone to a HTTP request smuggling vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Gunicorn does not properly validate Transfer-Encoding
  headers.");

  script_tag(name:"impact", value:"By crafting requests with conflicting Transfer-Encoding headers,
  attackers can bypass security restrictions and access restricted endpoints.");

  script_tag(name:"affected", value:"Gunicorn prior to version 22.0.0.");

  script_tag(name:"solution", value:"Update to version 22.0.0 or later.");

  script_xref(name:"URL", value:"https://huntr.com/bounties/22158e34-cfd5-41ad-97e0-a780773d96c1");
  script_xref(name:"URL", value:"https://github.com/benoitc/gunicorn/releases/tag/22.0.0");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "22.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "22.0.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
