# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807052");
  script_version("2025-01-17T15:39:18+0000");
  script_cve_id("CVE-2016-1930", "CVE-2016-1931", "CVE-2016-1933", "CVE-2016-1935",
                "CVE-2016-1939", "CVE-2015-7208", "CVE-2016-1937", "CVE-2016-1938",
                "CVE-2016-1943", "CVE-2016-1942", "CVE-2016-1944", "CVE-2016-1945",
                "CVE-2016-1946", "CVE-2016-1941", "CVE-2016-1978");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-01-29 09:52:58 +0530 (Fri, 29 Jan 2016)");
  script_name("Mozilla Firefox Multiple Vulnerabilities (Jan 2016) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple memory-corruption vulnerabilities.

  - An error in the image parsing code during the de-interlacing of a
    maliciously crafted GIF formatted image resulting in a possible integer
    overflow.

  - A buffer-overflow vulnerability.

  - A security bypass vulnerability, that allows for control characters to be
    set in cookie names.

  - A lack of delay following user click events in the protocol handler dialog,
    resulting in double click events to be treated as two single click events.

  - Calculations with mp_div and mp_exptmod in Network Security Services (NSS)
    can produce wrong results in some circumstances, leading to potential
    cryptographic weaknesses.

  - Multiple security bypass vulnerabilities exist for address bar spoofing
    attacks, that can lead to potential spoofing.

  - A Use-after-free vulnerability in the 'ssl3_HandleECDHServerKeyExchange'
    function.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  an attacker to bypass security restrictions and perform unauthorized actions,
  obtain sensitive information, bypass same-origin policy restrictions to
  access data, and execute arbitrary code in the context of the affected
  application. Failed exploit attempts will likely result in
  denial-of-service conditions.");

  script_tag(name:"affected", value:"Mozilla Firefox version before 44.");

  script_tag(name:"solution", value:"Update version 44 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/79280");
  script_xref(name:"URL", value:"http://msisac.cisecurity.org/advisories/2016/2016-018.cfm");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less(version:vers, test_version:"44.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"44.0");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
