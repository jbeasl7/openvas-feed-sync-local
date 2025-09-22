# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834782");
  script_version("2025-01-24T05:37:33+0000");
  script_cve_id("CVE-2024-11694");
  script_tag(name:"cvss_base", value:"4.2");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-01-24 05:37:33 +0000 (Fri, 24 Jan 2025)");
  script_tag(name:"creation_date", value:"2024-11-27 12:17:19 +0530 (Wed, 27 Nov 2024)");
  script_name("Mozilla Firefox ESR Security Update (MFSA2024-65) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to an enhanced
  tracking protection CSP frame-src bypass and DOM-based XSS vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a content security
  policy (CSP) frame-src bypass and a DOM-based XSS vulnerability in the web
  compatibility extension of Mozilla Firefox ESR, caused by enhanced tracking
  protection.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to bypass the Content Security Policy (CSP) frame-src directive using the
  google safeframe shim in the web compatibility extension and conduct
  DOM-based cross-site scripting (XSS) attacks.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR prior to version
  115.18 on Windows.");

  script_tag(name:"solution", value:"Update to version 115.18 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-65/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-64/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox-ESR/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"115.18")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"115.18", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
