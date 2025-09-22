# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:f5:big-ip";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105366");
  script_cve_id("CVE-2015-5477");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("2024-05-29T05:05:18+0000");

  script_name("F5 BIG-IP - BIND vulnerability CVE-2015-5477");

  script_xref(name:"URL", value:"https://my.f5.com/manage/s/article/K16909");

  script_tag(name:"impact", value:"A remote attacker may be able to cause a denial-of-service (DoS) attack on the BIG-IP system's local instance of BIND by using a specially crafted DNS request in configurations that expose BIND to requests from untrusted users.Note: If the BIND daemon stops responding, services that do not rely on the use of local instances of BIND will continue to function.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An error in the handling of TKEY queries can be exploited by an attacker for use as a denial-of-service vector, as a constructed packet can use the defect to trigger a REQUIRE assertion failure, causing BIND to exit. (CVE-2015-5477)");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"The remote host is missing a security patch.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2024-05-29 05:05:18 +0000 (Wed, 29 May 2024)");
  script_tag(name:"creation_date", value:"2015-09-18 15:17:44 +0200 (Fri, 18 Sep 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("F5 Local Security Checks");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_f5_big_ip_ssh_login_detect.nasl");
  script_mandatory_keys("f5/big_ip/version", "f5/big_ip/active_modules");
  exit(0);
}

include("f5.inc");
include("host_details.inc");
include("list_array_func.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, service: "ssh-login"))
  exit(0);

check_f5["LTM"] = make_array("affected",   "11.6.0;11.0.0-11.5.3;10.1.0-10.2.4;",
                             "unaffected", "12.0.0;11.6.0_HF6;11.5.4;11.5.3_HF2;11.4.1_HF9;11.2.1_HF15;10.2.4_HF12;");

check_f5["AAM"] = make_array("affected",   "11.6.0;11.4.0-11.5.3;",
                             "unaffected", "12.0.0;11.6.0_HF6;11.5.4;11.5.3_HF2;11.4.1_HF9;");

check_f5["AFM"] = make_array("affected",   "11.6.0;11.3.0-11.5.3;",
                             "unaffected", "12.0.0;11.6.0_HF6;11.5.4;11.5.3_HF2;11.4.1_HF9;");

check_f5["AVR"] = make_array("affected",   "11.6.01;11.0.0-11.5.31;",
                             "unaffected", "12.0.0;11.6.0_HF6;11.5.4;11.5.3_HF2;11.4.1_HF9;11.2.1_HF15;");

check_f5["APM"] = make_array("affected",   "11.6.0;11.0.0-11.5.3;10.1.0-10.2.4;",
                             "unaffected", "12.0.0;11.6.0_HF6;11.5.4;11.5.3_HF2;11.4.1_HF9;11.2.1_HF15;10.2.4_HF12;");

check_f5["ASM"] = make_array("affected",   "11.6.0;11.0.0-11.5.3;10.1.0-10.2.4;",
                             "unaffected", "12.0.0;11.6.0_HF6;11.5.4;11.5.3_HF2;11.4.1_HF9;11.2.1_HF15;10.2.4_HF12;");

check_f5["GTM"] = make_array("affected",   "11.6.0;11.0.0-11.5.3;10.1.0-10.2.4;",
                             "unaffected", "11.6.0_HF6;11.5.4;11.5.3_HF2;11.4.1_HF9;11.2.1_HF15;10.2.4_HF12;");

check_f5["LC"]  = make_array("affected",   "11.6.0;11.0.0-11.5.3;10.1.0-10.2.4;",
                             "unaffected", "12.0.0;11.6.0_HF6;11.5.4;11.5.3_HF2;11.4.1_HF9;11.2.1_HF15;10.2.4_HF12;");

check_f5["PEM"] = make_array("affected",   "11.6.0;11.3.0-11.5.3;",
                             "unaffected", "12.0.0;11.6.0_HF6;11.5.4;11.5.3_HF2;11.4.1_HF9;");

check_f5["PSM"] = make_array("affected",   "11.0.0-11.4.1;10.1.0-10.2.4;",
                             "unaffected", "11.4.1_HF9;11.2.1_HF15;10.2.4_HF12;");

check_f5["WAM"] = make_array("affected",   "11.0.0-11.3.0;10.1.0-10.2.4;",
                             "unaffected", "11.2.1_HF15;10.2.4_HF12;");

check_f5["WOM"] = make_array("affected",   "11.0.0-11.3.0;10.1.0-10.2.4;",
                             "unaffected", "11.2.1_HF15;10.2.4_HF12;");

if (report = f5_is_vulnerable(ca: check_f5, version: version)) {
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
