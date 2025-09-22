# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:lexmark:";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154143");
  script_version("2025-03-07T15:40:19+0000");
  script_tag(name:"last_modification", value:"2025-03-07 15:40:19 +0000 (Fri, 07 Mar 2025)");
  script_tag(name:"creation_date", value:"2025-03-07 03:33:38 +0000 (Fri, 07 Mar 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:N");

  script_cve_id("CVE-2020-10095");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Lexmark Printer CSRF Vulnerability (CVE-2020-10095)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_lexmark_printer_consolidation.nasl");
  script_mandatory_keys("lexmark_printer/detected");

  script_tag(name:"summary", value:"Multiple Lexmark printer devices are prone to a cross-site
  request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable firmware version is present on the
  target host.");

  script_tag(name:"insight", value:"Lexmark devices' embedded web server contains a cross-site
  request forgery attack vulnerability that allows the devices configuration to be altered without
  authorization.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability can lead to the
  modification of the configuration of the device.");

  script_tag(name:"solution", value:"See the referenced vendor advisories for a solution.");

  script_xref(name:"URL", value:"https://publications.lexmark.com/publications/security-alerts/CVE-2020-10095.pdf");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, first_cpe_only: TRUE))
  exit(0);

port = infos["port"];
cpe = infos["cpe"];

if (!version = toupper(get_app_version(cpe: cpe, port: port, nofork: TRUE)))
  exit(0);

if (cpe =~ "^cpe:/o:lexmark:b2236") {
  if (version_is_less(version: version, test_version: "MSLSG.072.203")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSLSG.072.203");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms[34]31" || cpe =~ "^cpe:/o:lexmark:m1241" ||
    cpe =~ "^cpe:/o:lexmark:b3442" || cpe =~ "^cpe:/o:lexmark:b3340") {
  if (version_is_less(version: version, test_version: "MSLBD.072.203")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSLBD.072.203");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mb2236") {
  if (version_is_less(version: version, test_version: "MXLSG.072.203")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXLSG.072.203");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx[34]31" || cpe =~ "^cpe:/o:lexmark:mb3442") {
  if (version_is_less(version: version, test_version: "MXLBD.072.203")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXLBD.072.203");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms521") {
  if (version_is_less(version: version, test_version: "MSNGM.072.203")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSNGM.072.203");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms62[12]" || cpe =~ "^cpe:/o:lexmark:m1246" ||
    cpe =~ "^cpe:/o:lexmark:m3250" || cpe =~ "^cpe:/o:lexmark:b2546" ||
    cpe =~ "^cpe:/o:lexmark:b2650") {
  if (version_is_less(version: version, test_version: "MSTGM.072.203")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSTGM.072.203");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx[45]21" || cpe =~ "^cpe:/o:lexmark:mx[56]22" ||
    cpe =~ "^cpe:/o:lexmark:xm124[26]" || cpe =~ "^cpe:/o:lexmark:xm3250" ||
    cpe =~ "^cpe:/o:lexmark:mb2546" || cpe =~ "^cpe:/o:lexmark:mb2650") {
  if (version_is_less(version: version, test_version: "MXTGM.072.203")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXTGM.072.203");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx321" || cpe =~ "^cpe:/o:lexmark:mb2338") {
  if (version_is_less(version: version, test_version: "MXNGM.072.203")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXNGM.072.203");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms725" || cpe =~ "^cpe:/o:lexmark:ms821") {
  if (version_is_less(version: version, test_version: "MSNGW.072.203")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSNGW.072.203");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms82[2356]" || cpe =~ "^cpe:/o:lexmark:m52(55|70)" ||
    cpe =~ "^cpe:/o:lexmark:b2865") {
  if (version_is_less(version: version, test_version: "MSTGW.072.203")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSTGW.072.203");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx72[12]" || cpe =~ "^cpe:/o:lexmark:mx82[26]" ||
    cpe =~ "^cpe:/o:lexmark:xm5365" || cpe =~ "^cpe:/o:lexmark:xm73(55|70)") {
  if (version_is_less(version: version, test_version: "MXTGW.072.203")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXTGW.072.203");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:c3426" || cpe =~ "^cpe:/o:lexmark:cs431") {
  if (version_is_less(version: version, test_version: "CSLBN.072.203")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSLBN.072.203");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs331" || cpe =~ "^cpe:/o:lexmark:c3224" ||
    cpe =~ "^cpe:/o:lexmark:c3326") {
  if (version_is_less(version: version, test_version: "CSLBL.072.203")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSLBL.072.203");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mc3426" || cpe =~ "^cpe:/o:lexmark:cx431") {
  if (version_is_less(version: version, test_version: "CXLBN.072.203")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXLBN.072.203");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mc3326" || cpe =~ "^cpe:/o:lexmark:mc3224" ||
    cpe =~ "^cpe:/o:lexmark:cx331") {
  if (version_is_less(version: version, test_version: "CXLBL.072.203")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXLBL.072.203");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs622" || cpe =~ "^cpe:/o:lexmark:c2240") {
  if (version_is_less(version: version, test_version: "CSTZJ.072.203")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTZJ.072.203");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs[45]21" || cpe =~ "^cpe:/o:lexmark:c2535" ||
    cpe =~ "^cpe:/o:lexmark:c2[34]25") {
  if (version_is_less(version: version, test_version: "CSNZJ.072.203")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSNZJ.072.203");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx[56]22" || cpe =~ "^cpe:/o:lexmark:cx625" ||
    cpe =~ "^cpe:/o:lexmark:xc2235" || cpe =~ "^cpe:/o:lexmark:xc4240" ||
    cpe =~ "^cpe:/o:lexmark:mc2535" || cpe =~ "^cpe:/o:lexmark:mc2640") {
  if (version_is_less(version: version, test_version: "CXTZJ.072.203")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTZJ.072.203");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx421" || cpe =~ "^cpe:/o:lexmark:mc2[34]25") {
  if (version_is_less(version: version, test_version: "CXNZJ.072.203")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXNZJ.072.203");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx82[05]" || cpe =~ "^cpe:/o:lexmark:cx860" ||
    cpe =~ "^cpe:/o:lexmark:xc6152" || cpe =~ "^cpe:/o:lexmark:xc81(55|60)") {
  if (version_is_less(version: version, test_version: "CXTPP.072.203")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTPP.072.203");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs820" || cpe =~ "^cpe:/o:lexmark:c6160") {
  if (version_is_less(version: version, test_version: "CSTPP.072.203")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTPP.072.203");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs72[05]" || cpe =~ "^cpe:/o:lexmark:c4150") {
  if (version_is_less(version: version, test_version: "CSTAT.072.203")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTAT.072.203");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx725" || cpe =~ "^cpe:/o:lexmark:xc41[45]0") {
  if (version_is_less(version: version, test_version: "CXTAT.072.203")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTAT.072.203");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs92[13]") {
  if (version_is_less(version: version, test_version: "CSTMH.072.203")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTMH.072.203");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx92[1-4]" || cpe =~ "^cpe:/o:lexmark:xc92[0-9]{2}") {
  if (version_is_less(version: version, test_version: "CXTMH.072.203")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTMH.072.203");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
