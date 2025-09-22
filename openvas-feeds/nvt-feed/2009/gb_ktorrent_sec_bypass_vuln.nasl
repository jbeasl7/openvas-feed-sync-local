# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800342");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-01-22 12:00:13 +0100 (Thu, 22 Jan 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-5905", "CVE-2008-5906");
  script_name("KTorrent PHP Code Injection And Security Bypass Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/32442");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31927");
  script_xref(name:"URL", value:"https://bugs.gentoo.org/show_bug.cgi?id=244741");
  script_xref(name:"URL", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=504178");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ktorrent_detect.nasl");
  script_mandatory_keys("KTorrent/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary PHP
  code and also bypass security restriction when affected web interface plugin
  is enabled.");
  script_tag(name:"affected", value:"KTorrent version prior to 3.1.4 on Linux.");
  script_tag(name:"insight", value:"The flaws are due to

  - sending improperly sanitised request into PHP interpreter. This can be
    exploited by injecting PHP code.

  - web interface plugin does not properly restrict access to the torrent
    upload functionality via HTTP POST request.");
  script_tag(name:"solution", value:"Upgrade to 3.1.4 or later.");
  script_tag(name:"summary", value:"KTorrent is prone to a security bypass vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ktVer = get_kb_item("KTorrent/Linux/Ver");
if(!ktVer)
  exit(0);

if(version_is_less(version:ktVer, test_version:"3.1.4")){
  report = report_fixed_ver(installed_version:ktVer, fixed_version:"3.1.4");
  security_message(port: 0, data: report);
}
