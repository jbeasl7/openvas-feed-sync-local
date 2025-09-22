# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805905");
  script_version("2024-10-10T07:25:31+0000");
  script_cve_id("CVE-2015-2721", "CVE-2015-2722", "CVE-2015-2724", "CVE-2015-2725",
                "CVE-2015-2726", "CVE-2015-2728", "CVE-2015-2729", "CVE-2015-2730",
                "CVE-2015-2731", "CVE-2015-2733", "CVE-2015-2734", "CVE-2015-2735",
                "CVE-2015-2736", "CVE-2015-2737", "CVE-2015-2738", "CVE-2015-2739",
                "CVE-2015-2740", "CVE-2015-2741", "CVE-2015-2743", "CVE-2015-4000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-20 15:15:00 +0000 (Wed, 20 Jan 2021)");
  script_tag(name:"creation_date", value:"2015-07-08 15:59:57 +0530 (Wed, 08 Jul 2015)");
  script_name("Mozilla Firefox Multiple Vulnerabilities-01 (Jul 2015) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An error within Network Security Services (NSS) where the client allows for
  a 'ECDHE_ECDSA' exchange where the server does not send its 'ServerKeyExchange'
  message.

  - Multiple use-after-free vulnerabilities.

  - Multiple unspecified memory related errors.

  - An error within the 'IndexedDatabaseManager' class in the IndexedDB
  implementation.

  - An error within the 'AudioParamTimeline::AudioNodeInputValue' function in the
  Web Audio implementation.

  - An error in the implementation of Elliptical Curve Cryptography (ECC)
  multiplication for Elliptic Curve Digital Signature Algorithm (ECDSA) signature
  validation in Network Security Services (NSS).

  - An error in the 'CairoTextureClientD3D9::BorrowDrawTarget' function in the
  Direct3D 9 implementation.

  - An error in 'nsZipArchive::BuildFileList' function.

  - Unspecified error in nsZipArchive.cpp script.

  - An error in the 'rx::d3d11::SetBufferData' function in the Direct3D 11
  implementation.

  - An error in the 'YCbCrImageDataDeserializer::ToDataSourceSurface' function
  in the YCbCr implementation.

  - An error in 'ArrayBufferBuilder::append' function.

  - Buffer overflow error in the 'nsXMLHttpRequest::AppendToResponseText' function.

  - An overridable error allowing for skipping pinning checks.

  - An error in PDF.js PDF file viewer.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code, obtain sensitive information, conduct
  man-in-the-middle attack, conduct denial-of-service attack, spoof ECDSA
  signatures and other unspecified impacts.");

  script_tag(name:"affected", value:"Mozilla Firefox before version 39.0 on
  Windows");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 39.0
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-59");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75541");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74733");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-66");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-67");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-69");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-64");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-62");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");

  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!ffVer = get_app_version(cpe:CPE)){
   exit(0);
}

if(version_is_less(version:ffVer, test_version:"39.0"))
{
  report = 'Installed version: ' + ffVer + '\n' +
           'Fixed version:     ' + "39.0"  + '\n';
  security_message(data:report);
  exit(0);
}
