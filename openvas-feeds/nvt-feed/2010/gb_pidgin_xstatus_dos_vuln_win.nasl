# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901137");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)");
  script_cve_id("CVE-2010-2528");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_name("Pidgin 'X-Status' Message Denial of Service Vulnerability - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40699");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41881");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/60566");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1887");
  script_xref(name:"URL", value:"http://www.pidgin.im/news/security/index.php?id=47");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_pidgin_detect_win.nasl");
  script_mandatory_keys("Pidgin/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause the application
  to crash, denying service to legitimate users.");
  script_tag(name:"affected", value:"Pidgin versions prior to 2.7.2");
  script_tag(name:"insight", value:"The flaw is caused by a NULL pointer dereference error when processing
  malformed 'X-Status' messages, which could be exploited by attackers to
  crash an affected application, creating a denial of service condition.");
  script_tag(name:"solution", value:"Upgrade to Pidgin version 2.7.2 or later.");
  script_tag(name:"summary", value:"Pidgin is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

pidginVer = get_kb_item("Pidgin/Win/Ver");

if(pidginVer != NULL)
{
  if(version_is_less(version:pidginVer, test_version:"2.7.2")){
    report = report_fixed_ver(installed_version:pidginVer, fixed_version:"2.7.2");
    security_message(port: 0, data: report);
  }
}

