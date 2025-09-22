# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900858");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-09-23 08:37:26 +0200 (Wed, 23 Sep 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-3265", "CVE-2009-3266");
  script_name("Opera Multiple Cross-Site Scripting Vulnerabilities (Sep 2009) - Linux");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/506517/100/0/threaded");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36418");
  script_xref(name:"URL", value:"http://securethoughts.com/2009/09/exploiting-chrome-and-operas-inbuilt-atomrss-reader-with-script-execution-and-more/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_opera_detection_linux_900037.nasl");
  script_mandatory_keys("Opera/Linux/Version");
  script_tag(name:"impact", value:"Attacker can exploit this issue to conduct XSS attacks to inject arbitrary web
script or HTML.");
  script_tag(name:"affected", value:"Opera version 9.x and 10.x on Linux.");
  script_tag(name:"insight", value:"An error in the application which can be exploited to obtain complete control
over feeds via a 'RSS' or 'Atom' feed. It is related to the rendering of the
application/rss+xml content type as 'scripted content.'.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Opera is prone to multiple Cross-Site Scripting vulnerabilities.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"executable_version");
  exit(0);
}



operaVer = get_kb_item("Opera/Linux/Version");
if(!operaVer){
  exit(0);
}

if(operaVer =~ "^(9|10)\..*"){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
