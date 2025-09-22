# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:foxitsoftware:reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811585");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2017-10952", "CVE-2017-10951");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:21:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-08-21 13:07:23 +0530 (Mon, 21 Aug 2017)");
  script_name("Foxit Reader Multiple 'Disabled safe reading mode' RCE Vulnerabilities - Windows");

  script_tag(name:"summary", value:"Foxit Reader is prone to multiple remote code execution (RCE)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The lack of proper validation of user-supplied data in the 'saveAs JavaScript' function, which
  can lead to writing arbitrary files into attacker controlled locations.

  - The lack of proper validation of a user-supplied string before using it to execute a system call
  in app.launchURL method.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  code under the context of the current process.");

  script_tag(name:"affected", value:"All Foxit Reader versions on Windows with 'Safe reading mode'
  feature disabled.");

  script_tag(name:"solution", value:"A mitigation is available:

  Safe reading mode should be enabled always and additionally users can also uncheck the 'Enable
  JavaScript Actions' from Foxit's Preferences menu, although this may break some functionality.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod", value:"30");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-691");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100412");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100409");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-692");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/blog/2017/8/17/busting-myths-in-foxit-reader");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_foxit_reader_detect_portable_win.nasl");
  script_mandatory_keys("foxit/reader/ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## All foxit reader installations are detected as vulnerable independent of version
## Because Foxit refused to patch both the vulnerabilities because they would not work with the
## "safe reading mode" feature that fortunately comes enabled by default in Foxit Reader.
if(!vers = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

report = report_fixed_ver(installed_version:vers, fixed_version:"Mitigation");
security_message(port:0, data:report);
exit(0);
