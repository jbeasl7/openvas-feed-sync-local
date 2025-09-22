# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803305");
  script_version("2025-08-01T05:45:36+0000");
  script_cve_id("CVE-2013-1450", "CVE-2013-1451");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-08-01 05:45:36 +0000 (Fri, 01 Aug 2025)");
  script_tag(name:"creation_date", value:"2013-02-04 11:45:52 +0530 (Mon, 04 Feb 2013)");
  script_name("Microsoft Internet Explorer Information Disclosure and Web Site Spoofing Vulnerabilities");
  script_xref(name:"URL", value:"http://pastebin.com/raw.php?i=rz9BcBey");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57640");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57641");
  script_xref(name:"URL", value:"http://cxsecurity.com/cveshow/CVE-2013-1450");
  script_xref(name:"URL", value:"http://cxsecurity.com/cveshow/CVE-2013-1451");
  script_xref(name:"URL", value:"http://www.security-database.com/detail.php?alert=CVE-2013-1450");
  script_xref(name:"URL", value:"http://www.security-database.com/detail.php?alert=CVE-2013-1451");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Windows");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to disclose the
  sensitive information and view the contents of spoofed site or carry out
  phishing attacks.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer versions 8 and 9.");

  script_tag(name:"insight", value:"The proxy settings configuration has same proxy address and value for HTTP
  and HTTPS,

  - TCP session to proxy server will not properly be reused. This allows remote
  attackers to steal cookie information via crafted HTML document.

  - SSl lock consistency with address bar is not ensured. This allows remote
  attackers to spoof web sites via a crafted HTML document.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Microsoft Internet Explorer is prone to information disclosure and web site spoofing vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

ieVer = get_kb_item("MS/IE/Version");

if(ieVer && ieVer =~ "^(8|9)"){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
