# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804271");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2014-1730", "CVE-2014-1731", "CVE-2014-1732", "CVE-2014-1733",
                "CVE-2014-1734", "CVE-2014-1735", "CVE-2014-1736");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-04-29 14:07:08 +0530 (Tue, 29 Apr 2014)");
  script_name("Google Chrome Multiple Vulnerabilities - 02 (Apr 2014) - Linux");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaws are due to:

  - Multiple unspecified errors in V8.

  - A type confusion error exists in v8.

  - A type confusion error exists within DOM.

  - A use-after-free error exists in Speech Recognition.

  - An error exists related to compilation of Seccomp-BPF.

  - Some unspecified errors exist.

  - Integer overflow in api.cc in Google V8.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct a denial of
service, bypass intended sandbox restrictions, compromise a user's system
or an unknown impact.");
  script_tag(name:"affected", value:"Google Chrome version prior to 34.0.1847.132 on Linux.");
  script_tag(name:"solution", value:"Upgrade to Google Chrome 34.0.1847.132 or later.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2014/04/stable-channel-update_24.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67082");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!chromeVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"34.0.1847.132"))
{
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"34.0.1847.132");
  security_message(port:0, data:report);
  exit(0);
}
