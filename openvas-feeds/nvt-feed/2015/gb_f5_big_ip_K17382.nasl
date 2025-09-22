# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:f5:big-ip";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105400");
  script_cve_id("CVE-2010-4252");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2024-05-29T05:05:18+0000");

  script_name("F5 BIG-IP - OpenSSL vulnerability CVE-2010-4252");

  script_xref(name:"URL", value:"https://my.f5.com/manage/s/article/K17382");

  script_tag(name:"impact", value:"F5 products do not use J-PAKE in supported configurations.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"OpenSSL before 1.0.0c, when J-PAKE is enabled, does not properly validate the public parameters in the J-PAKE protocol, which allows remote attackers to bypass the need for knowledge of the shared secret, and successfully authenticate, by sending crafted values in each round of the protocol. (CVE-2010-4252)");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"The remote host is missing a security patch.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2024-05-29 05:05:18 +0000 (Wed, 29 May 2024)");
  script_tag(name:"creation_date", value:"2015-10-14 12:16:35 +0200 (Wed, 14 Oct 2015)");
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

check_f5["LTM"] = make_array("affected",   "10.1.0-10.2.1;",
                             "unaffected", "12.0.0;11.0.0-11.6.0;10.2.2-10.2.4;");

check_f5["APM"] = make_array("affected",   "10.1.0-10.2.1;",
                             "unaffected", "12.0.0;11.0.0-11.6.0;10.2.2-10.2.4;");

check_f5["ASM"] = make_array("affected",   "10.1.0-10.2.1;",
                             "unaffected", "12.0.0;11.0.0-11.6.0;10.2.2-;10.2.4;");

check_f5["GTM"] = make_array("affected",   "10.1.0-10.2.1;",
                             "unaffected", "11.0.0-11.6.0;10.2.2-10.2.4;");

check_f5["LC"]  = make_array("affected",   "10.1.0-10.2.1;",
                             "unaffected", "12.0.0;11.0.0-11.6.0;10.2.2-10.2.4;");

check_f5["PSM"] = make_array("affected",   "10.1.0-10.2.1;",
                             "unaffected", "11.0.0-11.4.1;10.2.2-10.2.4;");

check_f5["WAM"] = make_array("affected",   "10.1.0-10.2.1;",
                             "unaffected", "11.0.0-11.3.0;10.2.2-10.2.4;");

check_f5["WOM"] = make_array("affected",   "10.1.0-10.2.1;",
                             "unaffected", "11.0.0-11.3.0;10.2.2-10.2.4;");

if (report = f5_is_vulnerable(ca: check_f5, version: version)) {
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
