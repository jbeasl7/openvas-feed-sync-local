# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mcafee:web_gateway";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811258");
  script_version("2024-03-01T14:37:10+0000");
  script_cve_id("CVE-2012-6706", "CVE-2017-1000364", "CVE-2017-1000366",
                "CVE-2017-1000368");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-03-01 14:37:10 +0000 (Fri, 01 Mar 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-21 10:29:00 +0000 (Sun, 21 Oct 2018)");
  script_tag(name:"creation_date", value:"2017-07-28 12:24:03 +0530 (Fri, 28 Jul 2017)");
  script_name("McAfee Web Gateway Multiple Vulnerabilities (SB10205)");

  script_tag(name:"summary", value:"McAfee Web Gateway is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An integer overflow error in 'DataSize+CurChannel' which results in a negative
    value of the 'DestPos' variable allowing to write out of bounds when setting
    Mem[DestPos].

  - An error in the size of the stack guard page on Linux, specifically a 4k stack
    guard page which is not sufficiently large and can be 'jumped' over (the stack
    guard page is bypassed).

  - An error in the glibc which allows specially crafted 'LD_LIBRARY_PATH' values
    to manipulate the heap/stack, causing them to alias.

  - An input validation (embedded newlines) error in the 'get_process_ttyname'
    function.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute an arbitrary code and gain privileged access to affected
  system.");

  script_tag(name:"affected", value:"McAfee Web Gateway before 7.6.2.15 and
  7.7.x before 7.7.2.3");

  script_tag(name:"solution", value:"Upgrade to McAfee Web Gateway version
  7.6.2.15 or 7.7.2.3 or later.");

  script_xref(name:"URL", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10205");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98838");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99127");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99130");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_mcafee_web_gateway_detect.nasl");
  script_mandatory_keys("McAfee/Web/Gateway/installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:version, test_version:"7.6.2.15")) {
  fix = "7.6.2.15";
}

if(version =~ "^7\.7" && version_is_less(version:version, test_version:"7.7.2.3")) {
  fix = "7.7.2.3";
}

if(fix) {
  report = report_fixed_ver( installed_version:version, fixed_version:fix);
  security_message( data:report, port:port);
  exit(0);
}

exit(99);
