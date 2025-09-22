# SPDX-FileCopyrightText: 2005 Noam Rathaus <noamr@securiteam.com> & SecuriTeam
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:verity:ultraseek";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10791");
  script_version("2025-07-22T05:43:35+0000");
  script_tag(name:"last_modification", value:"2025-07-22 05:43:35 +0000 (Tue, 22 Jul 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-1999-0996", "CVE-2000-1019");
  # nb: References are indicating that these have been fixed in 4.x versions. As the software is
  # highly outdated this should be enough for now.
  script_name("Infoseek / Verity Ultraseek < 4.x Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Noam Rathaus <noamr@securiteam.com> & SecuriTeam");
  script_family("Web application abuses");
  script_dependencies("gb_ultraseek_http_detect.nasl");
  script_mandatory_keys("ultraseek/detected");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210121153546/http://www.securityfocus.com/bid/1866");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121153049/http://www.securityfocus.com/bid/874");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/19679");
  script_xref(name:"URL", value:"https://marc.info/?l=bugtraq&m=97301487015664&w=2");

  script_tag(name:"summary", value:"Infoseek / Verity Ultraseek (formerly Inktomi Search) is prone
  to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Ultraseek has been known to contain security vulnerabilities
  ranging from buffer overflows to cross-site scripting (XSS) issues.");

  script_tag(name:"solution", value:"Make sure you are running the latest version of the Ultraseek
  or disable it if you do not use it.");

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

if (version_is_less(version: version, test_version: "4.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "Probably 4.0 or later", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
