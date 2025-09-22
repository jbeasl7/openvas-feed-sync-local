# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:apple:os_x_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810599");
  script_version("2023-11-03T05:05:46+0000");
  script_cve_id("CVE-2016-0751", "CVE-2007-6750", "CVE-2017-2382");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-12 01:29:00 +0000 (Wed, 12 Jul 2017)");
  script_tag(name:"creation_date", value:"2017-04-03 10:32:56 +0530 (Mon, 03 Apr 2017)");
  script_name("Apple OS X Server Denial of Service And User Enumeration Vulnerabilities");

  script_tag(name:"summary", value:"Apple OS X Server is prone to denial of service and user enumeration vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An insufficient permission check for access in Wiki server.

  - The partial HTTP requests in Web Server.

  - The caching for unknown MIME types, which can cause a global cache to grow
    indefinitely.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to enumerate users and cause a denial of service condition.");

  script_tag(name:"affected", value:"Apple OS X Server before 5.3");

  script_tag(name:"solution", value:"Upgrade to Apple OS X Server 5.3 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT207604");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/90690");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/90689");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_apple_macosx_server_detect.nasl");
  script_mandatory_keys("Apple/OSX/Server/Version", "ssh/login/osx_version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || version_is_less(version:osVer, test_version:"10.12.4")){
  exit(0);
}

if(!serVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:serVer, test_version:"5.3"))
{
  report = report_fixed_ver(installed_version:serVer, fixed_version:"5.3");
  security_message(data:report);
  exit(0);
}

exit(99);
