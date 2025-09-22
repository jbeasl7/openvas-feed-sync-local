# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806803");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2015-6788", "CVE-2015-6789", "CVE-2015-6790", "CVE-2015-6791",
                "CVE-2015-8548");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-12-16 15:04:13 +0530 (Wed, 16 Dec 2015)");
  script_name("Google Chrome Multiple Vulnerabilities-02 (Dec 2015) - Linux");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The no proper use of HTML entities in function
    'WebPageSerializerImp::openTagToString' in
    'WebKit/Source/web/WebPageSerializerImpl.cpp' file in the page serializer.

  - The difference in execution of multiple threads leading to race condition in
    the mutation implementation.

  - An improper implementation of handler functions in class
    ObjectBackedNativeHandler class which is in file
   'extensions/renderer/object_backed_native_handler.cc' in the extensions
    subsystem.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to cause denial of service or possibly have other impact, to inject
  arbitrary web script or HTML, bypass the security restrictions and gain access
  to potentially sensitive information.");

  script_tag(name:"affected", value:"Google Chrome versions prior to 47.0.2526.80
  on Linux.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  47.0.2526.80 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2015/12/stable-channel-update_8.html");

  script_copyright("Copyright (C) 2015 Greenbone AG");
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

if(version_is_less(version:chromeVer, test_version:"47.0.2526.80"))
{
  report = 'Installed version: ' + chromeVer + '\n' +
           'Fixed version:     47.0.2526.80'  + '\n';
  security_message(data:report);
  exit(0);
}
