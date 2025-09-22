# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800089");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-12-23 15:23:02 +0100 (Tue, 23 Dec 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5500", "CVE-2008-5501", "CVE-2008-5502", "CVE-2008-5503",
                "CVE-2008-5504", "CVE-2008-5505", "CVE-2008-5506", "CVE-2008-5507",
                "CVE-2008-5508", "CVE-2008-5510", "CVE-2008-5511", "CVE-2008-5512",
                "CVE-2008-5513");
  script_name("Mozilla Firefox Multiple Vulnerabilities (Dec 2008) - Linux");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-60.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32882");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-61.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-62.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-63.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-64.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-65.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-66.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-67.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-68.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-69.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_tag(name:"impact", value:"Successful exploitation could result in remote arbitrary code execution,
  bypass security restrictions, sensitive information disclosure, cross
  site scripting attacks and execute JavaScript code with chrome privileges.");

  script_tag(name:"affected", value:"Mozilla Firefox version prior to 2.0.0.19 and 3.x to 3.0.4.");

  script_tag(name:"solution", value:"Update to version 2.0.0.19, 3.0.5 or later.");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version:version, test_version:"2.0.0.19")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"2.0.0.19", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

if(version_in_range(version:version, test_version:"3.0", test_version2:"3.0.4")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"3.0.5", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
