# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:kaseya:virtual_system_administrator";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805927");
  script_version("2024-06-26T05:05:39+0000");
  script_cve_id("CVE-2015-2862", "CVE-2015-2863");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-06-26 05:05:39 +0000 (Wed, 26 Jun 2024)");
  script_tag(name:"creation_date", value:"2015-07-17 11:50:12 +0530 (Fri, 17 Jul 2015)");
  script_name("Kaseya Virtual System Administrator Multiple Vulnerabilities - Active Check");

  script_tag(name:"summary", value:"Kaseya Virtual System Administrator is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check
  whether it redirects to the malicious websites.");

  script_tag(name:"insight", value:"Multiple errors exist due to improper
  validation of input passed via 'urlToLoad' GET Parameter to supportLoad.asp
  script and 'filepath' GET Parameter to Downloader.ashx script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to download any arbitrary file, and create a specially crafted URL,
  that if clicked, would redirect  a victim from the intended legitimate web site
  to an arbitrary web site of the attacker's choosing.");

  script_tag(name:"affected", value:"Kaseya Virtual System Administrator
  versions 7.x before patch level 7.0.0.29, 8.x before patch level 8.0.0.18,
  9.x before patch level 9.0.0.14 and 9.1.x before patch level 9.1.0.4");

  script_tag(name:"solution", value:"Upgrade Kaseya Virtual System Administrator
  to patch level 7.0.0.29 or 8.0.0.18 or 9.0.0.14 or 9.1.0.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"exploit");

  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/919604");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75727");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75730");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/37621");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/535996");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Jul/63");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/pedrib/PoC/master/generic/kaseya-vsa-vuln.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_kaseya_vsa_detect.nasl");
  script_mandatory_keys("kaseya/vsa/http/detected");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit(0);

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/inc/supportLoad.asp?urlToLoad=http://www.example.com";

if( http_vuln_check( port:port, url:url, pattern:"(l|L)ocation.*http://www\.example\.com", extra_check:">Please wait" ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
