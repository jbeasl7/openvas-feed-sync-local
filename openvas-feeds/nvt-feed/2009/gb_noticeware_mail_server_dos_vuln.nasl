# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900463");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-02-26 05:27:20 +0100 (Thu, 26 Feb 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2008-6185");
  script_name("NoticeWare Mail Server Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_noticeware_mail_server_detect.nasl");
  script_mandatory_keys("NoticeWare/Mail/Server/Ver");

  script_xref(name:"URL", value:"http://secunia.com/advisories/32202");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31697");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/6719");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/45812");

  script_tag(name:"affected", value:"NoticeWare Mail Server version 5.1.2.2 and prior.");

  script_tag(name:"insight", value:"This flaw is due to an error when handling multiple POP3 connections. The
  server can crash when handling large number of POP3 connections issuing login requests.");

  script_tag(name:"summary", value:"NoticeWare Mail Server is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker cause denial of service.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("version_func.inc");

noticeVer = get_kb_item("NoticeWare/Mail/Server/Ver");
if(noticeVer && version_is_less_equal(version:noticeVer, test_version:"5.1.2.2")) {
  report = report_fixed_ver(installed_version:noticeVer, fixed_version:"WillNotFix");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);