# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openbsd:openssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813863");
  script_version("2023-07-20T05:05:18+0000");
  script_cve_id("CVE-2018-15473");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:18 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-23 23:13:00 +0000 (Thu, 23 Feb 2023)");
  script_tag(name:"creation_date", value:"2018-08-20 17:27:42 +0530 (Mon, 20 Aug 2018)");
  script_name("OpenSSH < 7.8 User Enumeration Vulnerability - Windows");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_openssh_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssh/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"https://0day.city/cve-2018-15473.html");
  script_xref(name:"URL", value:"https://github.com/openbsd/src/commit/779974d35b4859c07bc3cb8a12c74b43b0a7d1e0");

  script_tag(name:"summary", value:"OpenSSH is prone to a user enumeration vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to not delaying bailout for an invalid
  authenticating user until after the packet containing the request has been fully parsed, related
  to auth2-gss.c, auth2-hostbased.c, and auth2-pubkey.c");

  script_tag(name:"impact", value:"Successfully exploitation will allow remote attacker to test
  whether a certain user exists or not (username enumeration) on a target OpenSSH server.");

  script_tag(name:"affected", value:"OpenSSH versions 7.7 and prior.");

  script_tag(name:"solution", value:"Update to version 7.8 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"7.7")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.8", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);