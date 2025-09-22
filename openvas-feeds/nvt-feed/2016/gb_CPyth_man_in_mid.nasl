# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107021");
  script_version("2023-07-05T05:06:18+0000");
  script_cve_id("CVE-2013-7440");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:18 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"creation_date", value:"2016-07-04 19:31:49 +0200 (Mon, 04 Jul 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-28 19:10:00 +0000 (Mon, 28 Nov 2016)");
  script_name("CPython Man In The Middle Attack Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_python_consolidation.nasl");
  script_mandatory_keys("python/detected");

  script_tag(name:"summary", value:"CPython suffers from a man in the middle attack vulnerability
  via a crafted certificate.");

  script_tag(name:"insight", value:"The ssl.match_hostname function in CPython does not properly
  handle wildcards in hostnames, which might allow man-in-the-middle attackers to spoof servers
  via a crafted certificate.");

  script_tag(name:"impact", value:"Allows unauthorized modification.");

  script_tag(name:"affected", value:"CPython before 2.7.9 and 3.x before 3.3.3.");

  script_tag(name:"solution", value:"Update to version 2.7.9, 3.3.3 or later.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"^[0-9]+\.[0-9]+\.[0-9]+"))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^3\.[0-3]" && version_is_less(version:vers, test_version:"3.3.3")) {
  VUL = TRUE;
  fix = "3.3.3 or later";
}

else if(version_is_less(version:vers, test_version:"2.7.9")) {
  VUL = TRUE;
  fix = "2.7.9 or later";
}

if(VUL) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
