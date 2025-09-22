# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:lexmark:";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154123");
  script_version("2025-06-05T05:40:56+0000");
  script_tag(name:"last_modification", value:"2025-06-05 05:40:56 +0000 (Thu, 05 Jun 2025)");
  script_tag(name:"creation_date", value:"2025-03-05 03:29:07 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2024-11347");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Lexmark Printer RCE Vulnerability (CVE-2024-11347)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_lexmark_printer_consolidation.nasl");
  script_mandatory_keys("lexmark_printer/detected");

  script_tag(name:"summary", value:"Multiple Lexmark printer devices are prone to a remote code
  execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable firmware version is present on the
  target host.");

  script_tag(name:"insight", value:"An integer overflow has been identified in the Postscript
  interpreter in various Lexmark devices.");

  script_tag(name:"impact", value:"The vulnerability can be leveraged by an attacker to execute
  arbitrary code as an unprivileged user.");

  script_tag(name:"solution", value:"See the referenced vendor advisories for a solution.");

  script_xref(name:"URL", value:"https://support.lexmark.com/content/dam/support/collateral/security-alerts/CVE-2024-11347.pdf");

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

if (cpe =~ "^cpe:/o:lexmark:cx95[01]" || cpe =~ "^cpe:/o:lexmark:xc95[23]5") {
  if (version_is_equal(version: version, test_version: "CXTLS.240.200")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTLS.240.201");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx953") {
  if (version_is_equal(version: version, test_version: "MXTLS.240.200")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXTLS.240.201");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx96[1-3]" || cpe =~ "^cpe:/o:lexmark:xc96[3-5]5" ||
    cpe =~ "^cpe:/o:lexmark:cx833" || cpe =~ "^cpe:/o:lexmark:xc8355") {
  if (version_is_less(version: version, test_version: "CXTLS.240.077")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTLS.240.077");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "CXTLS.240.200")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTLS.240.201");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs963") {
  if (version_is_less(version: version, test_version: "CSTLS.240.077")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTLS.240.077");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "CSTLS.240.200")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTLS.240.201");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms[56]31") {
  if (version_is_less(version: version, test_version: "MSNSN.240.043")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSNSN.240.043");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "MSNSN.240.200")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSNSN.240.201");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms632" || cpe =~ "^cpe:/o:lexmark:m3350") {
  if (version_is_less(version: version, test_version: "MSTSN.240.043")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSTSN.240.043");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "MSTSN.240.200")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSTSN.240.201");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx[56]32" || cpe =~ "^cpe:/o:lexmark:xm3350") {
  if (version_is_less(version: version, test_version: "MXTSN.240.043")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXTSN.240.043");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "MXTSN.240.200")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXTSN.240.201");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs531" || cpe =~ "^cpe:/o:lexmark:c2335") {
  if (version_is_less(version: version, test_version: "CSNGV.240.043")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSNGV.240.043");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "CSNGV.240.200")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSNGV.240.201");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs632") {
  if (version_is_less(version: version, test_version: "CSTGV.240.043")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTGV.240.043");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "CSTGV.240.200")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTGV.240.201");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx532" || cpe =~ "^cpe:/o:lexmark:cx635" ||
    cpe =~ "^cpe:/o:lexmark:xc2335") {
  if (version_is_less(version: version, test_version: "CXTGV.240.043")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTGV.240.043");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "CXTGV.240.200")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTGV.240.201");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx9(30|31|42|43|44)" || cpe =~ "^cpe:/o:lexmark:xc93[23]5" ||
    cpe =~ "^cpe:/o:lexmark:xc94[4-6]5") {
  if (version_is_less(version: version, test_version: "CXTPC.240.043")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTPC.240.043");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "CXTPC.240.200")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTPC.240.201");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs943") {
  if (version_is_less(version: version, test_version: "CSTPC.240.043")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTPC.240.043");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "CSTPC.240.200")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTPC.240.201");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx432" || cpe =~ "^cpe:/o:lexmark:xm3142") {
  if (version_is_less(version: version, test_version: "MXTCT.240.043")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXTCT.240.043");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "MXTCT.240.200")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXTCT.240.201");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx931") {
  if (version_is_less(version: version, test_version: "MXTPM.240.043")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXTPM.240.043");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "MXTPM.240.200")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXTPM.240.201");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx73[057]" || cpe =~ "^cpe:/o:lexmark:xc43[45]2") {
  if (version_is_less(version: version, test_version: "CXTMM.240.043")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTMM.240.043");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "CXTMM.240.200")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTMM.240.201");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs73[057]" || cpe =~ "^cpe:/o:lexmark:c43[45]2") {
  if (version_is_less(version: version, test_version: "CSTMM.240.043")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTMM.240.043");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "CSTMM.240.200")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTMM.240.201");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:b2236") {
  if (version_is_less(version: version, test_version: "MSLSG.230.402")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSLSG.230.402");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mb2236") {
  if (version_is_less(version: version, test_version: "MXLSG.230.402")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXLSG.230.402");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms331" || cpe =~ "^cpe:/o:lexmark:ms43[19]" ||
    cpe =~ "^cpe:/o:lexmark:m1342" || cpe =~ "^cpe:/o:lexmark:b3442" ||
    cpe =~ "^cpe:/o:lexmark:b3340") {
  if (version_is_less(version: version, test_version: "MSLBD.230.402")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSLBD.230.402");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:xm1342" || cpe =~ "^cpe:/o:lexmark:mx[34]31" ||
    cpe =~ "^cpe:/o:lexmark:mb3442") {
  if (version_is_less(version: version, test_version: "MXLBD.230.402")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXLBD.230.402");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms[3-6]21" || cpe =~ "^cpe:/o:lexmark:m124[26]" ||
    cpe =~ "^cpe:/o:lexmark:b2338" || cpe =~ "^cpe:/o:lexmark:b2442" ||
    cpe =~ "^cpe:/o:lexmark:b2546" || cpe =~ "^cpe:/o:lexmark:b2650") {
  if (version_is_less(version: version, test_version: "MSNGM.230.402")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSNGM.230.402");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms622" || cpe =~ "^cpe:/o:lexmark:m3250") {
  if (version_is_less(version: version, test_version: "MSTGM.230.402")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSTGM.230.402");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx321" || cpe =~ "^cpe:/o:lexmark:mb2338") {
  if (version_is_less(version: version, test_version: "MXNGM.230.402")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXNGM.230.402");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx[45]21" || cpe =~ "^cpe:/o:lexmark:mx[56]22" ||
    cpe =~ "^cpe:/o:lexmark:xm124[26]" || cpe =~ "^cpe:/o:lexmark:xm3250" ||
    cpe =~ "^cpe:/o:lexmark:mb2442" || cpe =~ "^cpe:/o:lexmark:mb2546" ||
    cpe =~ "^cpe:/o:lexmark:mb2650") {
  if (version_is_less(version: version, test_version: "MXTGM.230.402")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXTGM.230.402");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms725" || cpe =~ "^cpe:/o:lexmark:ms82[135]" ||
    cpe =~ "^cpe:/o:lexmark:b2865") {
  if (version_is_less(version: version, test_version: "MSNGW.230.402")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSNGW.230.402");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms82[26]" || cpe =~ "^cpe:/o:lexmark:m52(55|70)") {
  if (version_is_less(version: version, test_version: "MSTGW.230.402")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSTGW.230.402");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx72[125]" || cpe =~ "^cpe:/o:lexmark:mx82[26]" ||
    cpe =~ "^cpe:/o:lexmark:xm53(65|70)" || cpe =~ "^cpe:/o:lexmark:xm73(55|70)" ||
    cpe =~ "^cpe:/o:lexmark:mb2770") {
  if (version_is_less(version: version, test_version: "MXTGW.230.402")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXTGW.230.402");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:c3426" || cpe =~ "^cpe:/o:lexmark:cs43[19]" ||
    cpe =~ "^cpe:/o:lexmark:c2326") {
  if (version_is_less(version: version, test_version: "CSLBN.230.402")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSLBN.230.402");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs331" || cpe =~ "^cpe:/o:lexmark:c3224" ||
    cpe =~ "^cpe:/o:lexmark:c3326") {
  if (version_is_less(version: version, test_version: "CSLBL.230.402")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSLBL.230.402");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mc3426" || cpe =~ "^cpe:/o:lexmark:cx431" ||
    cpe =~ "^cpe:/o:lexmark:xc2326" || cpe =~ "^cpe:/o:lexmark:mc3426") {
  if (version_is_less(version: version, test_version: "CXLBN.230.402")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXLBN.230.402");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mc3224" || cpe =~ "^cpe:/o:lexmark:mc3326" ||
    cpe =~ "^cpe:/o:lexmark:cx331") {
  if (version_is_less(version: version, test_version: "CXLBL.230.402")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXLBL.230.402");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs622" || cpe =~ "^cpe:/o:lexmark:c2240") {
  if (version_is_less(version: version, test_version: "CSTZJ.230.402")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTZJ.230.402");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs[45]21" || cpe =~ "^cpe:/o:lexmark:c2[34]25" ||
    cpe =~ "^cpe:/o:lexmark:c2535") {
  if (version_is_less(version: version, test_version: "CSNZJ.230.402")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSNZJ.230.402");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx[56]22" || cpe =~ "^cpe:/o:lexmark:cx625" ||
    cpe =~ "^cpe:/o:lexmark:xc2235" || cpe =~ "^cpe:/o:lexmark:xc4240" ||
    cpe =~ "^cpe:/o:lexmark:mc2535" || cpe =~ "^cpe:/o:lexmark:mc2640") {
  if (version_is_less(version: version, test_version: "CXTZJ.230.402")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTZJ.230.402");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx421" || cpe =~ "^cpe:/o:lexmark:mc2[34]25") {
  if (version_is_less(version: version, test_version: "CXNZJ.230.402")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXNZJ.230.402");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx82[057]" || cpe =~ "^cpe:/o:lexmark:cx860" ||
    cpe =~ "^cpe:/o:lexmark:xc615[23]" || cpe =~ "^cpe:/o:lexmark:xc81(55|60|63)") {
  if (version_is_less(version: version, test_version: "CXTPP.230.402")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTPP.230.402");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs82[07]" || cpe =~ "^cpe:/o:lexmark:c6160") {
  if (version_is_less(version: version, test_version: "CSTPP.230.402")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTPP.230.402");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs72[0578]" || cpe =~ "^cpe:/o:lexmark:c4150") {
  if (version_is_less(version: version, test_version: "CSTAT.230.402")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTAT.230.402");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx72[57]" || cpe =~ "^cpe:/o:lexmark:xc41(40|43|50|53)") {
  if (version_is_less(version: version, test_version: "CXTAT.230.402")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTAT.230.402");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs92[137]" || cpe =~ "^cpe:/o:lexmark:c9235") {
  if (version_is_less(version: version, test_version: "CSTMH.230.402")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTMH.230.402");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx92[0-4]" || cpe =~ "^cpe:/o:lexmark:xc92[2-6]5") {
  if (version_is_less(version: version, test_version: "CXTMH.230.402")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTMH.230.402");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms315" || cpe =~ "^cpe:/o:lexmark:ms41[57]") {
  if (version_is_less(version: version, test_version: "LW90.TL2.P216")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW90.TL2.P216");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms51[07]" || cpe =~ "^cpe:/o:lexmark:ms610dn" ||
    cpe =~ "^cpe:/o:lexmark:ms617" || cpe =~ "^cpe:/o:lexmark:m114[05]" ||
    cpe =~ "^cpe:/o:lexmark:m3150dn") {
  if (version_is_less(version: version, test_version: "LW90.PR2.P216")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW90.PR2.P216");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms610de" || cpe =~ "^cpe:/o:lexmark:m3150de") {
  if (version_is_less(version: version, test_version: "LW90.PR4.P216")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW90.PR4.P216");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx41[07]" || cpe =~ "^cpe:/o:lexmark:mx51[017]" ||
    cpe =~ "^cpe:/o:lexmark:xm114[05]") {
  if (version_is_less(version: version, test_version: "LW90.SB4.P216")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW90.SB4.P216");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx61[017]" || cpe =~ "^cpe:/o:lexmark:xm3150") {
  if (version_is_less(version: version, test_version: "LW90.SB7.P216")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW90.SB7.P216");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms71[01]" || cpe =~ "^cpe:/o:lexmark:ms81[02]dn" ||
    cpe =~ "^cpe:/o:lexmark:ms81[178]" || cpe =~ "^cpe:/o:lexmark:m5163dn") {
  if (version_is_less(version: version, test_version: "LW90.DN2.P216")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW90.DN2.P216");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms810de" || cpe =~ "^cpe:/o:lexmark:m5155" ||
    cpe =~ "^cpe:/o:lexmark:m5163de") {
  if (version_is_less(version: version, test_version: "LW90.DN4.P216")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW90.DN4.P216");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms812de" || cpe =~ "^cpe:/o:lexmark:m5170") {
  if (version_is_less(version: version, test_version: "LW90.DN7.P216")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW90.DN7.P216");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx71[0178]" || cpe =~ "^cpe:/o:lexmark:mx81[012]" ||
    cpe =~ "^cpe:/o:lexmark:xm5[12](63|70)" || cpe =~ "^cpe:/o:lexmark:xm71(55|63|70)" ||
    cpe =~ "^cpe:/o:lexmark:xm72(63|70)") {
  if (version_is_less(version: version, test_version: "LW90.TU.P216")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW90.TU.P216");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms911") {
  if (version_is_less(version: version, test_version: "LW90.SA.P216")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW90.SA.P216");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx91[0-2]" || cpe =~ "^cpe:/o:lexmark:xm91[4-6]5") {
  if (version_is_less(version: version, test_version: "LW90.MG.P216")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW90.MG.P216");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx51[07]" || cpe =~ "^cpe:/o:lexmark:xc2132") {
  if (version_is_less(version: version, test_version: "LW90.GM7.P216")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW90.GM7.P216");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:xc2130" || cpe =~ "^cpe:/o:lexmark:cx41[07]") {
  if (version_is_less(version: version, test_version: "LW90.GM4.P216")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW90.GM4.P216");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs51[07]" || cpe =~ "^cpe:/o:lexmark:c2132") {
  if (version_is_less(version: version, test_version: "LW90.VY4.P216")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW90.VY4.P216");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms31[027]" || cpe =~ "^cpe:/o:lexmark:ms410" ||
    cpe =~ "^cpe:/o:lexmark:m1140") {
  if (version_is_less(version: version, test_version: "LW80.PRL.P258")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.PRL.P258");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx31[07]" || cpe =~ "^cpe:/o:lexmark:xm1135") {
  if (version_is_less(version: version, test_version: "LW80.SB2.P258")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.SB2.P258");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs31[07]") {
  if (version_is_less(version: version, test_version: "LW80.VYL.P258")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.VYL.P258");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs41[07]") {
  if (version_is_less(version: version, test_version: "LW80.VY2.P258")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.VY2.P258");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx31[07]") {
  if (version_is_less(version: version, test_version: "LW80.GM2.P258")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW80.GM2.P258");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
