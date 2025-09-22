# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800876");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-09-02 11:50:45 +0200 (Wed, 02 Sep 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-3007");
  script_name("Mozilla Products Address Bar Spoofing Vulnerability - Linux");
  script_xref(name:"URL", value:"http://lostmon.blogspot.com/2009/08/multiple-browsers-fake-url-folder-file.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl", "gb_seamonkey_detect_lin.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Linux/Installed");
  script_tag(name:"impact", value:"Successful exploitation lets the attackers to spoof parts of the
address bar and modify page content on a host that a user may consider partly
trusted.");
  script_tag(name:"affected", value:"Mozilla Firefox version 3.5.1 and 3.5.2

  Mozilla Seamonkey 1.1.17.");
  script_tag(name:"insight", value:"Error exists when opening a new window using 'window.open()',
which can be exploited to display spoofed content in the browser window while
the address bar shows an arbitrary path on a possibly trusted host.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Mozilla Products are prone to an address bar spoofing vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Linux/Ver");

if(ffVer)
{
  if(version_is_equal(version:ffVer, test_version:"3.5.1")||
     version_is_equal(version:ffVer, test_version:"3.5.2"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

smVer = get_kb_item("Seamonkey/Linux/Ver");

if(smVer != NULL)
{
  if(version_is_equal(version:smVer, test_version:"1.1.17")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
