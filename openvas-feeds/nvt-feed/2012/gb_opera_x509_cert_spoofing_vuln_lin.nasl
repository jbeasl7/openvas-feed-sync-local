# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802436");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2012-1251");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-06-12 16:15:21 +0530 (Tue, 12 Jun 2012)");
  script_name("Opera 'X.509' Certificates Spoofing Vulnerability - Linux");
  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN39707339/index.html");
  script_xref(name:"URL", value:"http://www.opera.com/docs/changelogs/unix/963/");
  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2012/JVNDB-2012-000049.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_opera_detection_linux_900037.nasl");
  script_mandatory_keys("Opera/Linux/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to spoof servers and
  obtain sensitive information.");
  script_tag(name:"affected", value:"Opera version prior to 9.63 on Linux");
  script_tag(name:"insight", value:"The flaw is due to an error in handling of certificates, it does not properly
  verify 'X.509' certificates from SSL servers.");
  script_tag(name:"solution", value:"Upgrade to Opera 9.63 or later.");
  script_tag(name:"summary", value:"Opera is prone to a spoofing vulnerability");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

operaVer = get_kb_item("Opera/Linux/Version");
if(!operaVer){
  exit(0);
}

if(version_is_less(version:operaVer, test_version:"9.63")){
  report = report_fixed_ver(installed_version:operaVer, fixed_version:"9.63");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
