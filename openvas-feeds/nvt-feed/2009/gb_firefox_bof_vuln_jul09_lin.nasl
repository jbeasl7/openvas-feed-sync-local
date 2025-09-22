# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800847");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-07-18 09:37:41 +0200 (Sat, 18 Jul 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2009-2478", "CVE-2009-2479");
  script_name("Mozilla Firefox Buffer Overflow Vulnerability (Jul 2009) - Linux");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9158");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35707");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/51729");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=503286");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");
  script_tag(name:"impact", value:"Successful attacks will let attackers to can cause Denial of Service to the
  legitimate user.");
  script_tag(name:"affected", value:"Mozilla Firefox version 3.5.1 and prior.");
  script_tag(name:"insight", value:"- A NULL pointer dereference error exists due an unspecified vectors, related
    to a 'flash bug.' which can cause application crash.

  - Stack-based buffer overflow error is caused by sending an overly long string
    argument to the 'document.write' method.");
  script_tag(name:"solution", value:"Update to version 3.6.3 or later.");
  script_tag(name:"summary", value:"Mozilla Firefox is prone to a buffer overflow vulnerability.");
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

if(version_is_less_equal(version:version, test_version:"3.5.1")){
  report = report_fixed_ver(installed_version:version, fixed_version:"3.6.3", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
