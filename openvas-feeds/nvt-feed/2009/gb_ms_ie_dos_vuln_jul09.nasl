# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800669");
  script_version("2024-02-19T05:05:57+0000");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-07-22 21:36:53 +0200 (Wed, 22 Jul 2009)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2009-2536", "CVE-2009-1692");
  script_name("Microsoft Internet Explorer Denial Of Service Vulnerability (Jul 2009)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");

  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9160");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35446");
  script_xref(name:"URL", value:"http://www.g-sec.lu/one-bug-to-rule-them-all.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/504969/100/0/threaded");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause a denial of
  service by exhausting memory.");

  script_tag(name:"affected", value:"Internet Explorer Version 5.x, 6.x, 7.x and 8.x.");

  script_tag(name:"insight", value:"Error exists while calling the select method with a large
  integer, that results in continuous allocation of x+n bytes of memory exhausting
  memory after a while.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Internet Explorer is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("version_func.inc");

if(!ieVer = get_kb_item("MS/IE/Version")) exit(0);

if(version_in_range(version:ieVer, test_version:"5.0", test_version2:"8.0.6001.18702")) {
  report = report_fixed_ver(installed_version:ieVer, fixed_version:"N/A");
  security_message(data:report);
  exit(0);
}

exit(99);
