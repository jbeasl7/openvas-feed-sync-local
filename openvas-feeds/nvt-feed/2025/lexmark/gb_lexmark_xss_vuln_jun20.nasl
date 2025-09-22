# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:lexmark:";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154159");
  script_version("2025-03-11T05:38:16+0000");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"creation_date", value:"2025-03-10 09:08:04 +0000 (Mon, 10 Mar 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");

  script_cve_id("CVE-2020-13481");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Lexmark Printer XSS Vulnerability (CVE-2020-13481)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_lexmark_printer_consolidation.nasl");
  script_mandatory_keys("lexmark_printer/detected");

  script_tag(name:"summary", value:"Multiple Lexmark printer devices are prone to a stored
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable firmware version is present on the
  target host.");

  script_tag(name:"insight", value:"A stored cross-site scripting vulnerability has been identified
  in the embedded web server used in Lexmark devices.");

  script_tag(name:"impact", value:"The vulnerability can be used to attack the user's browser,
  exposing session credentials and other information accessible to the browser.");

  script_tag(name:"solution", value:"See the referenced vendor advisories for a solution.");

  script_xref(name:"URL", value:"https://publications.lexmark.com/publications/security-alerts/CVE-2020-13481.pdf");

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
  if (version_in_range(version: version, test_version: "MSLSG.073.022", test_version2: "MSLSG.073.023") ||
      version_is_equal(version: version, test_version: "MSLSG.072.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSLSG.072.210 / MSLSG.073.225");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms[34]31" || cpe =~ "^cpe:/o:lexmark:m1241" ||
    cpe =~ "^cpe:/o:lexmark:b3442" || cpe =~ "^cpe:/o:lexmark:b3340") {
  if (version_in_range(version: version, test_version: "MSLBD.073.022", test_version2: "MSLBD.073.023") ||
      version_is_equal(version: version, test_version: "MSLBD.072.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSLBD.072.210 / MSLBD.073.225");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mb2236") {
  if (version_in_range(version: version, test_version: "MXLSG.073.022", test_version2: "MXLSG.073.023") ||
      version_is_equal(version: version, test_version: "MXLSG.072.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXLSG.072.210 / MXLSG.073.225");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx[34]31" || cpe =~ "^cpe:/o:lexmark:mb3442") {
  if (version_in_range(version: version, test_version: "MXLBD.073.022", test_version2: "MXLBD.073.023") ||
      version_is_equal(version: version, test_version: "MXLBD.072.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXLBD.072.210 / MXLBD.073.225");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms521") {
  if (version_in_range(version: version, test_version: "MSNGM.073.022", test_version2: "MSNGM.073.023") ||
      version_is_equal(version: version, test_version: "MSNGM.072.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSNGM.072.210 / MSNGM.073.225");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms62[12]" || cpe =~ "^cpe:/o:lexmark:m1246" ||
    cpe =~ "^cpe:/o:lexmark:m3250" || cpe =~ "^cpe:/o:lexmark:b2546" ||
    cpe =~ "^cpe:/o:lexmark:b2650") {
  if (version_in_range(version: version, test_version: "MSTGM.073.022", test_version2: "MSTGM.073.023") ||
      version_is_equal(version: version, test_version: "MSTGM.072.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSTGM.072.210 / MSTGM.073.225");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx[45]21" || cpe =~ "^cpe:/o:lexmark:mx[56]22" ||
    cpe =~ "^cpe:/o:lexmark:xm124[26]" || cpe =~ "^cpe:/o:lexmark:xm3250" ||
    cpe =~ "^cpe:/o:lexmark:mb2546" || cpe =~ "^cpe:/o:lexmark:mb2650") {
  if (version_in_range(version: version, test_version: "MXTGM.073.022", test_version2: "MXTGM.073.023") ||
      version_is_equal(version: version, test_version: "MXTGM.072.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXTGM.072.210 / MXTGM.073.225");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx321" || cpe =~ "^cpe:/o:lexmark:mb2338") {
  if (version_in_range(version: version, test_version: "MXNGM.073.022", test_version2: "MXNGM.073.023") ||
      version_is_equal(version: version, test_version: "MXNGM.072.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXNGM.072.210 / MXNGM.073.225");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms725" || cpe =~ "^cpe:/o:lexmark:ms821") {
  if (version_in_range(version: version, test_version: "MSNGW.073.022", test_version2: "MSNGW.073.023") ||
      version_is_equal(version: version, test_version: "MSNGW.072.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSNGW.072.210 / MSNGW.073.225");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms82[2356]" || cpe =~ "^cpe:/o:lexmark:m52(55|70)" ||
    cpe =~ "^cpe:/o:lexmark:b2865") {
  if (version_in_range(version: version, test_version: "MSTGW.073.022", test_version2: "MSTGW.073.023") ||
      version_is_equal(version: version, test_version: "MSTGW.072.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSTGW.072.210 / MSTGW.073.225");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx72[12]" || cpe =~ "^cpe:/o:lexmark:mx82[26]" ||
    cpe =~ "^cpe:/o:lexmark:xm5365" || cpe =~ "^cpe:/o:lexmark:xm73(55|70)") {
  if (version_in_range(version: version, test_version: "MXTGW.073.022", test_version2: "MXTGW.073.023") ||
      version_is_equal(version: version, test_version: "MXTGW.072.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXTGW.072.210 / MXTGW.073.225");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:c3426" || cpe =~ "^cpe:/o:lexmark:cs431") {
  if (version_in_range(version: version, test_version: "CSLBN.073.022", test_version2: "CSLBN.073.023") ||
      version_is_equal(version: version, test_version: "CSLBN.072.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSLBN.072.210 / CSLBN.073.225");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs331" || cpe =~ "^cpe:/o:lexmark:c3224" ||
    cpe =~ "^cpe:/o:lexmark:c3326") {
  if (version_in_range(version: version, test_version: "CSLBL.073.022", test_version2: "CSLBL.073.023") ||
      version_is_equal(version: version, test_version: "CSLBL.072.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSLBL.072.210 / CSLBL.073.225");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mc3426" || cpe =~ "^cpe:/o:lexmark:cx431") {
  if (version_in_range(version: version, test_version: "CXLBN.073.022", test_version2: "CXLBN.073.023") ||
      version_is_equal(version: version, test_version: "CXLBN.072.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXLBN.072.210 / CXLBN.073.225");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mc3326" || cpe =~ "^cpe:/o:lexmark:mc3224" ||
    cpe =~ "^cpe:/o:lexmark:cx331") {
  if (version_in_range(version: version, test_version: "CXLBL.073.022", test_version2: "CXLBL.073.023") ||
      version_is_equal(version: version, test_version: "CXLBL.072.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXLBL.072.210 / CXLBL.073.225");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs622" || cpe =~ "^cpe:/o:lexmark:c2240") {
  if (version_in_range(version: version, test_version: "CSTZJ.073.022", test_version2: "CSTZJ.073.023") ||
      version_is_equal(version: version, test_version: "CSTZJ.072.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTZJ.072.210 / CSTZJ.073.225");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs[45]21" || cpe =~ "^cpe:/o:lexmark:c2535" ||
    cpe =~ "^cpe:/o:lexmark:c2[34]25") {
  if (version_in_range(version: version, test_version: "CSNZJ.073.022", test_version2: "CSNZJ.073.023") ||
      version_is_equal(version: version, test_version: "CSNZJ.072.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSNZJ.072.210 / CSNZJ.073.225");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx[56]22" || cpe =~ "^cpe:/o:lexmark:cx625" ||
    cpe =~ "^cpe:/o:lexmark:xc2235" || cpe =~ "^cpe:/o:lexmark:xc4240" ||
    cpe =~ "^cpe:/o:lexmark:mc2535" || cpe =~ "^cpe:/o:lexmark:mc2640") {
  if (version_in_range(version: version, test_version: "CXTZJ.073.022", test_version2: "CXTZJ.073.023") ||
      version_is_equal(version: version, test_version: "CXTZJ.072.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTZJ.072.210 / CXTZJ.073.225");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx421" || cpe =~ "^cpe:/o:lexmark:mc2[34]25") {
  if (version_in_range(version: version, test_version: "CXNZJ.073.022", test_version2: "CXNZJ.073.023") ||
      version_is_equal(version: version, test_version: "CXNZJ.072.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXNZJ.072.210 / CXNZJ.073.225");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx82[05]" || cpe =~ "^cpe:/o:lexmark:cx860" ||
    cpe =~ "^cpe:/o:lexmark:xc6152" || cpe =~ "^cpe:/o:lexmark:xc81(55|60)") {
  if (version_in_range(version: version, test_version: "CXTPP.073.022", test_version2: "CXTPP.073.023") ||
      version_is_equal(version: version, test_version: "CXTPP.072.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTPP.072.210 / CXTPP.073.225");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs820" || cpe =~ "^cpe:/o:lexmark:c6160") {
  if (version_in_range(version: version, test_version: "CSTPP.073.022", test_version2: "CSTPP.073.023") ||
      version_is_equal(version: version, test_version: "CSTPP.072.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTPP.072.210 / CSTPP.073.225");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs72[05]" || cpe =~ "^cpe:/o:lexmark:c4150") {
  if (version_in_range(version: version, test_version: "CSTAT.073.022", test_version2: "CSTAT.073.023") ||
      version_is_equal(version: version, test_version: "CSTAT.072.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTAT.072.210 / CSTAT.073.225");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx725" || cpe =~ "^cpe:/o:lexmark:xc41[45]0") {
  if (version_in_range(version: version, test_version: "CXTAT.073.022", test_version2: "CXTAT.073.023") ||
      version_is_equal(version: version, test_version: "CXTAT.072.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTAT.072.210 / CXTAT.073.225");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs92[13]") {
  if (version_in_range(version: version, test_version: "CSTMH.073.022", test_version2: "CSTMH.073.023") ||
      version_is_equal(version: version, test_version: "CSTMH.072.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTMH.072.210 / CSTMH.073.225");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx92[1-4]" || cpe =~ "^cpe:/o:lexmark:xc92[0-9]{2}") {
  if (version_in_range(version: version, test_version: "CXTMH.073.022", test_version2: "CXTMH.073.023") ||
      version_is_equal(version: version, test_version: "CXTMH.072.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTMH.072.210 / CXTMH.073.225");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs31[0-9]") {
  if (version_is_less(version: version, test_version: "LW75.VYL.P279")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW75.VYL.P279");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs41[0-9]") {
  if (version_is_less(version: version, test_version: "LW75.VY2.P279")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW75.VY2.P279");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs51[0-9]") {
  if (version_is_less(version: version, test_version: "LW75.VY4.P279")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW75.VY4.P279");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx310") {
  if (version_is_less(version: version, test_version: "LW75.GM2.P279")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW75.GM2.P279");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx410" || cpe =~ "^cpe:/o:lexmark:xc2130") {
  if (version_is_less(version: version, test_version: "LW75.GM4.P279")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW75.GM4.P279");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx510" || cpe =~ "^cpe:/o:lexmark:xc2132") {
  if (version_is_less(version: version, test_version: "LW75.GM7.P279")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW75.GM7.P279");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms31[027]" || cpe =~ "^cpe:/o:lexmark:ms410" ||
    cpe =~ "^cpe:/o:lexmark:m1140") {
  if (version_is_less(version: version, test_version: "LW75.PRL.P279")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW75.PRL.P279");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms315" || cpe =~ "^cpe:/o:lexmark:ms41[57]") {
  if (version_is_less(version: version, test_version: "LW75.TL2.P279")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW75.TL2.P279");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms51[0-9]" || cpe =~ "^cpe:/o:lexmark:ms610dn" ||
    cpe =~ "^cpe:/o:lexmark:ms617" || cpe =~ "^cpe:/o:lexmark:m1145" ||
    cpe =~ "^cpe:/o:lexmark:m3150dn") {
  if (version_is_less(version: version, test_version: "LW75.PR2.P279")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW75.PR2.P279");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms610de" || cpe =~ "^cpe:/o:lexmark:m3150") {
  if (version_is_less(version: version, test_version: "LW75.PR4.P279")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW75.PR4.P279");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms81[01278]") {
  if (version_is_less(version: version, test_version: "LW75.DN2.P279")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW75.DN2.P279");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms810de" || cpe =~ "^cpe:/o:lexmark:m51(55|63)") {
  if (version_is_less(version: version, test_version: "LW75.DN4.P279")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW75.DN4.P279");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms812de" || cpe =~ "^cpe:/o:lexmark:m5170") {
  if (version_is_less(version: version, test_version: "LW75.DN7.P279")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW75.DN7.P279");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms91[0-9]") {
  if (version_is_less(version: version, test_version: "LW75.SA.P279")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW75.SA.P279");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx31[0-9]" || cpe =~ "^cpe:/o:lexmark:xm1135") {
  if (version_is_less(version: version, test_version: "LW75.SB2.P279")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW75.SB2.P279");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx410" || cpe =~ "^cpe:/o:lexmark:mx51[01]" ||
    cpe =~ "^cpe:/o:lexmark:xm114[05]") {
  if (version_is_less(version: version, test_version: "LW75.SB4.P279")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW75.SB4.P279");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx61[01]" || cpe =~ "^cpe:/o:lexmark:xm3150") {
  if (version_is_less(version: version, test_version: "LW75.SB7.P279")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW75.SB7.P279");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx[78]1[0-9]" || cpe =~ "^cpe:/o:lexmark:xm[57]1[0-9]{2}") {
  if (version_is_less(version: version, test_version: "LW75.TU.P279")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW75.TU.P279");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx91[0-9]" || cpe =~ "^cpe:/o:lexmark:xm91[0-9]") {
  if (version_is_less(version: version, test_version: "LW75.MG.P279")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW75.MG.P279");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx6500e") {
  if (version_is_less(version: version, test_version: "LW75.JD.P279")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW75.JD.P279");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:c746") {
  if (version_is_less(version: version, test_version: "LHS60.CM2.P739")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LHS60.CM2.P739");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs?748") {
  if (version_is_less(version: version, test_version: "LHS60.CM4.P739")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LHS60.CM4.P739");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:c792" || cpe =~ "^cpe:/o:lexmark:cs796") {
  if (version_is_less(version: version, test_version: "LHS60.HC.P739")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LHS60.HC.P739");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:c925") {
  if (version_is_less(version: version, test_version: "LHS60.HV.P739")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LHS60.HV.P739");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:c950") {
  if (version_is_less(version: version, test_version: "LHS60.TP.P739")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LHS60.TP.P739");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:xs?548") {
  if (version_is_less(version: version, test_version: "LHS60.VK.P739")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LHS60.VK.P739");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:x74[0-9]" || cpe =~ "^cpe:/o:lexmark:xs748") {
  if (version_is_less(version: version, test_version: "LHS60.NY.P739")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LHS60.NY.P739");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:x792" || cpe =~ "^cpe:/o:lexmark:xs79[0-9]") {
  if (version_is_less(version: version, test_version: "LHS60.MR.P739")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LHS60.MR.P739");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:xs?925") {
  if (version_is_less(version: version, test_version: "LHS60.HK.P739")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LHS60.HK.P739");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:xs?95[0-9]") {
  if (version_is_less(version: version, test_version: "LHS60.TQ.P739")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LHS60.TQ.P739");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:6500e") {
  if (version_is_less(version: version, test_version: "LHS60.JR.P739")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LHS60.JR.P739");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:c734") {
  if (version_is_less(version: version, test_version: "LR.SK.P826")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LR.SK.P826");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:c736") {
  if (version_is_less(version: version, test_version: "LR.SKE.P826")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LR.SKE.P826");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:e46[0-9]") {
  if (version_is_less(version: version, test_version: "LR.LBH.P826")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LR.LBH.P826");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:t65[0-9]") {
  if (version_is_less(version: version, test_version: "LR.JP.P826")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LR.JP.P826");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:x46[0-9]") {
  if (version_is_less(version: version, test_version: "LR.BS.P826")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LR.BS.P826");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:x65[0-9]") {
  if (version_is_less(version: version, test_version: "LR.MN.P826")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LR.MN.P826");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:x73[0-9]") {
  if (version_is_less(version: version, test_version: "LR.FL.P826")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LR.FL.P826");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:w850") {
  if (version_is_less(version: version, test_version: "LP.JB.P825")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LP.JB.P825");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:x86[0-9]") {
  if (version_is_less(version: version, test_version: "LP.SP.P825")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LP.SP.P825");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
