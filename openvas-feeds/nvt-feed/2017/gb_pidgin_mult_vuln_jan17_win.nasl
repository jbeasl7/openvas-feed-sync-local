# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:pidgin:pidgin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809862");
  script_version("2024-02-20T14:37:13+0000");
  script_cve_id("CVE-2016-2365", "CVE-2016-2366", "CVE-2016-2367", "CVE-2016-2368",
                "CVE-2016-2369", "CVE-2016-2370", "CVE-2016-2371", "CVE-2016-2372",
                "CVE-2016-2373", "CVE-2016-2374", "CVE-2016-2375", "CVE-2016-2376",
                "CVE-2016-2377", "CVE-2016-2378", "CVE-2016-2380", "CVE-2016-4323",
                "CVE-2016-1000030");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-20 14:37:13 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-14 19:34:00 +0000 (Wed, 14 Nov 2018)");
  script_tag(name:"creation_date", value:"2017-01-18 13:03:03 +0530 (Wed, 18 Jan 2017)");
  script_name("Pidgin Multiple Vulnerabilities (Jan 2017) - Windows");

  script_tag(name:"summary", value:"Pidgin is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple errors exist due to:

  - the X.509 certificates may be improperly imported when using GnuTLS

  - an improper validation in the field and attribute counts

  - an improper validation of the incoming message format

  - an improper validation of the received values

  - an error in chunk decoding

  - not checking the field count before accessing the fields

  - multiple issues in the MXit protocol support

  - an error in g_vsnprintf()

  - an improper validation of the data length in the MXit protocol support

  - an improper usage of data types in the MXit protocol support

  - not checking the length of the font tag");

  script_tag(name:"impact", value:"Successful exploitation of these
  vulnerabilities will allow attackers to cause denial of service, execute
  arbitrary code and disclose information from memory.");

  script_tag(name:"affected", value:"Pidgin before version 2.11.0 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Pidgin version 2.11.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.pidgin.im/news/security");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91335");
  script_xref(name:"URL", value:"http://www.talosintelligence.com/reports/TALOS-2016-0133");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_pidgin_detect_win.nasl");
  script_mandatory_keys("Pidgin/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!pidVer = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less(version:pidVer, test_version:"2.11.0")) {
  report = report_fixed_ver(installed_version:pidVer, fixed_version:"2.11.0");
  security_message(data:report);
  exit(0);
}

exit(99);
