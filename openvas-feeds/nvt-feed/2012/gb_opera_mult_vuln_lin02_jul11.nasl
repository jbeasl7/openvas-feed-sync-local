# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802741");
  script_version("2024-02-16T05:06:55+0000");
  script_cve_id("CVE-2011-2635", "CVE-2011-2634", "CVE-2011-2636", "CVE-2011-2637",
                "CVE-2011-2638", "CVE-2011-2639", "CVE-2011-2640");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-04-10 12:16:51 +0530 (Tue, 10 Apr 2012)");
  script_name("Opera Browser Multiple Vulnerabilities-02 (Jul 2011) - Linux");
  script_xref(name:"URL", value:"http://www.opera.com/docs/changelogs/unix/1110/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48569");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_tag(name:"solution_type", value:"VendorFix");
  script_dependencies("secpod_opera_detection_linux_900037.nasl");
  script_mandatory_keys("Opera/Linux/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary code
  and cause a denial of service.");
  script_tag(name:"affected", value:"Opera Web Browser version prior 11.10 on Linux");
  script_tag(name:"insight", value:"The flaws are due to

  - An error in cascading Style Sheets (CSS) implementation, allows attackers
    to cause denial of service via vectors involving use of the hover pseudo
    class.

  - A Hijacking searches and other customisations in Opera.

  - An error Tomato Firmware v1.28.1816 Status Device List page in Opera.

  - Crashes on futura-sciences.com, seoptimise.com, mitosyfraudes.org.

  - Crash occurring with games on zylom.com.

  - A Hidden animated '.gif' causing high CPU load, because of constant repaints.

  - A crash when passing empty parameter to a Java applet.");
  script_tag(name:"solution", value:"Upgrade to Opera Web Browser version 11.10 or later.");
  script_tag(name:"summary", value:"Opera browser is prone to multiple vulnerabilities.");
  exit(0);
}

include("version_func.inc");

operaVer = get_kb_item("Opera/Linux/Version");
if(!operaVer){
  exit(0);
}

if(version_is_less(version:operaVer, test_version:"11.10")){
  report = report_fixed_ver(installed_version:operaVer, fixed_version:"11.10");
  security_message(port:0, data:report);
}
