# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802935");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2011-4922");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-08-17 17:21:39 +0530 (Fri, 17 Aug 2012)");
  script_name("Pidgin 'Libpurple' Cipher API Information Disclosure Vulnerability - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/43271/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46307");
  script_xref(name:"URL", value:"http://www.pidgin.im/news/security/?id=50");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2012/01/04/13");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_pidgin_detect_win.nasl");
  script_mandatory_keys("Pidgin/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to gain sensitive information.");
  script_tag(name:"affected", value:"Pidgin version prior 2.7.10 on Windows");
  script_tag(name:"insight", value:"The flaw is due to the 'md5_uninit()', 'md4_uninit()', 'des_uninit()',
  'des3_uninit()', 'rc4_uninit()', and 'purple_cipher_context_destroy()'
  functions in libpurple/cipher.c not properly clearing certain sensitive
  structures, which can lead to potentially sensitive information disclosure
  remaining in memory.");
  script_tag(name:"solution", value:"Upgrade to Pidgin version 2.7.10 or later.");
  script_tag(name:"summary", value:"Pidgin is prone to an information disclosure vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

pidginVer = get_kb_item("Pidgin/Win/Ver");
if(pidginVer)
{
  if(version_is_less(version:pidginVer, test_version:"2.7.10")){
    report = report_fixed_ver(installed_version:pidginVer, fixed_version:"2.7.10");
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);
