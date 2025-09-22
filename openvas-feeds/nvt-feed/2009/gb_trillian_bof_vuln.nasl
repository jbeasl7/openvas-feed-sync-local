# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800265");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-04-07 07:29:53 +0200 (Tue, 07 Apr 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-6563");
  script_name("Trillian Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/41782");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/28747");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/490772/100/0/threaded");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_trillian_detect.nasl");
  script_mandatory_keys("Trillian/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary code or
  to cause denial of service.");
  script_tag(name:"affected", value:"Trillian IM Client version 3.1.9.0 and prior.");
  script_tag(name:"insight", value:"The application fails to perform adequate boundary checks on user supplied
  data resulting in a parsing error while processing malformed DTD files.");
  script_tag(name:"solution", value:"Upgrade to Trillian IM Client version 4.2 or later.");
  script_tag(name:"summary", value:"Trillian is prone to a buffer overflow vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

version = get_kb_item("Trillian/Ver");
if(!version)
  exit(0);

if(version_is_less(version:version, test_version:"3.1.9.0")){
  report = report_fixed_ver(installed_version:version, fixed_version:"3.1.9.0");
  security_message(port: 0, data: report);
}
