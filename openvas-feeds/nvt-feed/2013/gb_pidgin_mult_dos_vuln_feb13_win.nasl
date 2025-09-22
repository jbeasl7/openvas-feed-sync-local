# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803308");
  script_version("2024-02-08T05:05:59+0000");
  script_cve_id("CVE-2013-0271", "CVE-2013-0272", "CVE-2013-0273", "CVE-2013-0274");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-02-20 19:21:44 +0530 (Wed, 20 Feb 2013)");
  script_name("Pidgin Multiple Denial of Service Vulnerabilities (Feb 2013) - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/52178");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57951");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57952");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57954");
  script_xref(name:"URL", value:"http://www.pidgin.im/news/security/?id=65");
  script_xref(name:"URL", value:"http://www.pidgin.im/news/security/?id=66");
  script_xref(name:"URL", value:"http://www.pidgin.im/news/security/?id=67");
  script_xref(name:"URL", value:"http://www.pidgin.im/news/security/?id=68");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_pidgin_detect_win.nasl");
  script_mandatory_keys("Pidgin/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary code,
  overwrite arbitrary local files or cause a denial of service.");
  script_tag(name:"affected", value:"Pidgin versions prior to 2.10.7");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - MXit protocol in libpurple saves an image to local disk using a filename.

  - Buffer overflow in http.c via HTTP header.

  - Does not properly terminate long user IDs, in sametime.c in libpurple.

  - upnp.c in libpurple fails to null-terminate strings in UPnP responses.");
  script_tag(name:"solution", value:"Upgrade to Pidgin version 2.10.7 or later.");
  script_tag(name:"summary", value:"Pidgin is prone to multiple denial of service vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

pidginVer = get_kb_item("Pidgin/Win/Ver");

if(pidginVer != NULL)
{
  if(version_is_less(version:pidginVer, test_version:"2.10.7"))
  {
    report = report_fixed_ver(installed_version:pidginVer, fixed_version:"2.10.7");
    security_message(port: 0, data: report);
    exit(0);
  }
}
