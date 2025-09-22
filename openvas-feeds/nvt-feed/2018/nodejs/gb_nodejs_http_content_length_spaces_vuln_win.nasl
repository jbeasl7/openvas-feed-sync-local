# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nodejs:node.js";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813472");
  script_version("2025-06-09T05:41:14+0000");
  script_cve_id("CVE-2018-7159");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-06-09 05:41:14 +0000 (Mon, 09 Jun 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-13 15:55:00 +0000 (Thu, 13 Feb 2020)");
  script_tag(name:"creation_date", value:"2018-07-09 17:20:49 +0530 (Mon, 09 Jul 2018)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Node.js Improper Input Validation Vulnerability (Mar 2018) - Windows");

  script_tag(name:"summary", value:"Node.js is prone to an improper input validation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error in the HTTP parser which ignores
  spaces in the Content-Length header, allowing input such as Content-Length: 1 2 to be interpreted
  as having a value of 12.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to send
  spaces in the Content-Length header and bypass 'Content-Length' restriction policy.");

  script_tag(name:"affected", value:"Node.js versions 4.x prior to 4.9.0, 6.x prior to 6.14.0, 8.x
  prior to 8.11.0 and 9.x prior to 9.10.0.");

  script_tag(name:"solution", value:"Update to version 4.9.0, 6.14.0, 8.11.0, 9.10.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/march-2018-security-releases/");

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_nodejs_smb_login_detect.nasl");
  script_mandatory_keys("nodejs/smb-login/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^4\." && version_is_less(version:vers, test_version:"4.9.0"))
  fix = "4.9.0";

else if(vers =~ "^6\." && version_is_less(version:vers, test_version:"6.14.0"))
  fix = "6.14.0";

else if(vers =~ "^8\." && version_is_less(version:vers, test_version:"8.11.0"))
  fix = "8.11.0";

else if(vers =~ "^9\." && version_is_less(version:vers, test_version:"9.10.0"))
  fix = "9.10.0";

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);