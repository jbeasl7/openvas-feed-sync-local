# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806778");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2015-8045", "CVE-2015-8047", "CVE-2015-8048", "CVE-2015-8049",
                "CVE-2015-8050", "CVE-2015-8418", "CVE-2015-8454", "CVE-2015-8455",
                "CVE-2015-8055", "CVE-2015-8056", "CVE-2015-8057", "CVE-2015-8058",
                "CVE-2015-8059", "CVE-2015-8060", "CVE-2015-8061", "CVE-2015-8062",
                "CVE-2015-8063", "CVE-2015-8064", "CVE-2015-8065", "CVE-2015-8066",
                "CVE-2015-8067", "CVE-2015-8068", "CVE-2015-8069", "CVE-2015-8070",
                "CVE-2015-8071", "CVE-2015-8401", "CVE-2015-8402", "CVE-2015-8403",
                "CVE-2015-8404", "CVE-2015-8405", "CVE-2015-8406", "CVE-2015-8407",
                "CVE-2015-8408", "CVE-2015-8409", "CVE-2015-8410", "CVE-2015-8411",
                "CVE-2015-8412", "CVE-2015-8413", "CVE-2015-8414", "CVE-2015-8415",
                "CVE-2015-8416", "CVE-2015-8417", "CVE-2015-8419", "CVE-2015-8420",
                "CVE-2015-8421", "CVE-2015-8422", "CVE-2015-8423", "CVE-2015-8424",
                "CVE-2015-8425", "CVE-2015-8426", "CVE-2015-8427", "CVE-2015-8428",
                "CVE-2015-8429", "CVE-2015-8430", "CVE-2015-8431", "CVE-2015-8432",
                "CVE-2015-8433", "CVE-2015-8434", "CVE-2015-8435", "CVE-2015-8436",
                "CVE-2015-8437", "CVE-2015-8438", "CVE-2015-8439", "CVE-2015-8440",
                "CVE-2015-8441", "CVE-2015-8442", "CVE-2015-8443", "CVE-2015-8444",
                "CVE-2015-8445", "CVE-2015-8446", "CVE-2015-8447", "CVE-2015-8448",
                "CVE-2015-8449", "CVE-2015-8450", "CVE-2015-8451", "CVE-2015-8452",
                "CVE-2015-8453", "CVE-2015-8456", "CVE-2015-8457", "CVE-2015-8652",
                "CVE-2015-8653", "CVE-2015-8654", "CVE-2015-8655", "CVE-2015-8656",
                "CVE-2015-8657", "CVE-2015-8822", "CVE-2015-8658", "CVE-2015-8820",
                "CVE-2015-8821", "CVE-2015-8823");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-15 18:57:00 +0000 (Mon, 15 May 2023)");
  script_tag(name:"creation_date", value:"2015-12-10 13:31:37 +0530 (Thu, 10 Dec 2015)");
  script_name("Adobe Flash Player Multiple Vulnerabilities (Dec 2015) - Windows");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple heap buffer overflow vulnerabilities.

  - Multiple memory corruption vulnerabilities.

  - Multiple security bypass vulnerabilities.

  - A stack overflow vulnerability.

  - A type confusion vulnerability.

  - An integer overflow vulnerability.

  - A buffer overflow vulnerability.

  - Multiple use-after-free vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to bypass security restrictions and execute arbitrary code on the affected
  system.");

  script_tag(name:"affected", value:"Adobe Flash Player version before
  18.0.0.268 and 19.x and 20.x before 20.0.0.228 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version
  18.0.0.268 or 20.0.0.228 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-32.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/78717");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/78718");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/78715");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/78714");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/78716");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/78712");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/78710");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/78715");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/78713");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Win/Installed");

  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!playerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:playerVer, test_version:"19.0", test_version2:"20.0.0.227"))
{
  fix = "20.0.0.228";
  VULN = TRUE;
}

else if(version_is_less(version:playerVer, test_version:"18.0.0.268"))
{
  fix = "18.0.0.268";
  VULN = TRUE;
}

if(VULN)
{
  report = 'Installed version: ' + playerVer + '\n' +
           'Fixed version:' + fix + '\n';
  security_message(data:report);
  exit(0);
}
