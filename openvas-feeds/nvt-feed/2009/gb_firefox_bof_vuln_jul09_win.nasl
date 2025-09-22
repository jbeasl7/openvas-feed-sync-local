# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800846");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-07-18 09:37:41 +0200 (Sat, 18 Jul 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2009-2478", "CVE-2009-2479");
  script_name("Mozilla Firefox Buffer Overflow Vulnerability (Jul 2009) - Windows");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9158");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35707");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/51729");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=503286");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  script_tag(name:"impact", value:"Successful attacks will let attackers to can cause Denial of Service to the
  legitimate user.");
  script_tag(name:"affected", value:"Firefox version 3.5.1 and prior on Windows");
  script_tag(name:"insight", value:"- A NULL pointer dereference error exists due an unspecified vectors, related
    to a 'flash bug.' which can cause application crash.

  - Stack-based buffer overflow error is caused by sending an overly long string
    argument to the 'document.write' method.");
  script_tag(name:"solution", value:"Upgrade to  Firefox version 3.6.3 or later.");
  script_tag(name:"summary", value:"Mozilla Firefox browser is prone to a buffer overflow vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Firefox/Win/Ver");
if(!vers)
  exit(0);

if(version_is_less_equal(version:vers, test_version:"3.5.1")){
  report = report_fixed_ver(installed_version:vers, vulnerable_range:"Less than or equal to 3.5.1");
  security_message(port: 0, data: report);
}
