# SPDX-FileCopyrightText: 2005 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:verity:ultraseek";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.17226");
  script_version("2025-07-22T05:43:35+0000");
  script_tag(name:"last_modification", value:"2025-07-22 05:43:35 +0000 (Tue, 22 Jul 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2005-0514");
  script_name("Infoseek / Verity Ultraseek < 5.3.3 XSS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("gb_ultraseek_http_detect.nasl");
  script_mandatory_keys("ultraseek/detected");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210128183223/http://www.securityfocus.com/bid/12617");

  script_tag(name:"summary", value:"Infoseek / Verity Ultraseek (formerly Inktomi Search) is
  vulnerable to cross-site scripting (XSS) and remote script injection due to a lack of sanitization
  of user-supplied data.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation of this issue may allow an attacker to
  execute malicious script code on a vulnerable server.");

  script_tag(name:"solution", value:"Update to version 5.3.3 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

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

if (version_is_less(version: version, test_version: "5.3.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
