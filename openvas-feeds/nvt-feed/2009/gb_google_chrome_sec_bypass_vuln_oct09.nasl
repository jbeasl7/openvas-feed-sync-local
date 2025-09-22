# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801108");
  script_version("2024-02-19T05:05:57+0000");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-10-06 07:21:15 +0200 (Tue, 06 Oct 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-3456");
  script_name("Google Chrome CA SSL Certificate Security Bypass Vulnerability (Oct 2009)");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/386075.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36479");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"impact", value:"Successfully exploitation will allow attackers to perform
man-in-the-middle attacks or impersonate trusted servers, which will aid in
further attack.");
  script_tag(name:"affected", value:"Google Chrome version 3.0.193.21 and prior on Windows.");
  script_tag(name:"insight", value:"Google Chrome fails to properly validate '\0' character in the
domain name in a signed CA certificate, allowing attackers to substitute malicious
SSL certificates for trusted ones.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Google Chrome Web Browser is prone to a security bypass vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(isnull(chromeVer)){
  exit(0);
}

if(version_is_less_equal(version:chromeVer, test_version:"3.0.195.21")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

exit(99);
