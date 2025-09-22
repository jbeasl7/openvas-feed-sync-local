# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dedecms:dedecms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126920");
  script_version("2025-06-09T05:41:14+0000");
  script_tag(name:"last_modification", value:"2025-06-09 05:41:14 +0000 (Mon, 09 Jun 2025)");
  script_tag(name:"creation_date", value:"2024-06-06 07:12:58 +0000 (Thu, 06 Jun 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-04 14:28:44 +0000 (Fri, 04 Apr 2025)");

  script_cve_id("CVE-2024-3143", "CVE-2024-3144", "CVE-2024-3145", "CVE-2024-3146",
                "CVE-2024-3147", "CVE-2024-3148", "CVE-2024-4585", "CVE-2024-4586",
                "CVE-2024-4587", "CVE-2024-4588", "CVE-2024-4589", "CVE-2024-4590",
                "CVE-2024-4591", "CVE-2024-4592", "CVE-2024-4593", "CVE-2024-4594",
                "CVE-2024-4790", "CVE-2024-28429", "CVE-2024-28430", "CVE-2024-28431",
                "CVE-2024-28432", "CVE-2024-28665", "CVE-2024-28666", "CVE-2024-28667",
                "CVE-2024-28668", "CVE-2024-28669", "CVE-2024-28670", "CVE-2024-28671",
                "CVE-2024-28672", "CVE-2024-28673", "CVE-2024-28674", "CVE-2024-28675",
                "CVE-2024-28676", "CVE-2024-28677", "CVE-2024-28678", "CVE-2024-28679",
                "CVE-2024-28680", "CVE-2024-28681", "CVE-2024-28682", "CVE-2024-28683",
                "CVE-2024-28684", "CVE-2024-29660", "CVE-2024-29661", "CVE-2024-29684",
                "CVE-2024-30946", "CVE-2024-30965", "CVE-2024-33371", "CVE-2024-33401",
                "CVE-2024-33749", "CVE-2024-34245", "CVE-2024-35375", "CVE-2024-35510",
                "CVE-2024-6940");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("DedeCMS V5.7 SP2 Multiple Vulnerabilities (Mar/Apr/May/Jul 2024)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dedecms_http_detect.nasl");
  script_mandatory_keys("dedecms/detected");

  script_tag(name:"summary", value:"DedeCMS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-3143, CVE-2024-3144, CVE-2024-3145, CVE-2024-3146, CVE-2024-3147, CVE-2024-4585,
  CVE-2024-4586, CVE-2024-4587, CVE-2024-4588, CVE-2024-4589, CVE-2024-4590, CVE-2024-4591,
  CVE-2024-4592, CVE-2024-4593, CVE-2024-4594, CVE-2024-28429, CVE-2024-28430, CVE-2024-28431,
  CVE-2024-28432, CVE-2024-28665, CVE-2024-28666, CVE-2024-28667, CVE-2024-28668, CVE-2024-28669,
  CVE-2024-28670, CVE-2024-28671, CVE-2024-28672, CVE-2024-28673, CVE-2024-28675, CVE-2024-28677,
  CVE-2024-28678, CVE-2024-28678, CVE-2024-28680, CVE-2024-28681, CVE-2024-28682, CVE-2024-28684,
  CVE-2024-29684, CVE-2024-30946, CVE-2024-30965: Multiple cross-site request forgery (CSRF)
  vulnerabilities

  - CVE-2024-3148: SQL injetcion (SQLi) via the unknown processing of the file
  dede/makehtml_archives_action.php

  - CVE-2024-4790: Path traversal via unknown part of the file /sys_verifies.php.

  - CVE-2024-28676, CVE-2024-28679, CVE-2024-28683, CVE-2024-29660, CVE-2024-33371, CVE-2024-33401:
  Multiple cross-site scripting (XSS) vulnerabilities

  - CVE-2024-29661: DedeCMS allows to execute arbitrary code via a crafted payload.

  - CVE-2024-33749: DedeCMS allows to deletion of any file via mail_file_manage.php.

  - CVE-2024-34245: An arbitrary file read vulnerability in DedeCMS allows authenticated attackers
  to read arbitrary files by specifying any path in makehtml_js_action.php.

  - CVE-2024-35375, CVE-2024-35510: Multiple arbitrary file upload vulnerabilities

  - CVE-2024-6940: A code injection vulnerability");

  script_tag(name:"affected", value:"All versions of DedeCMS V5.7 SP2 (5.7.114) and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one.");

  script_xref(name:"URL", value:"https://github.com/E1CHO/demo/blob/main/39.pdf");
  script_xref(name:"URL", value:"https://github.com/Hckwzh/cms/blob/main/12.md");
  script_xref(name:"URL", value:"https://github.com/Hckwzh/cms/blob/main/13.md");
  script_xref(name:"URL", value:"https://github.com/Hckwzh/cms/blob/main/14.md");
  script_xref(name:"URL", value:"https://github.com/Hckwzh/cms/blob/main/15.md");
  script_xref(name:"URL", value:"https://vuldb.com/?id.258923");
  script_xref(name:"URL", value:"https://github.com/Hckwzh/cms/blob/main/16.md");
  script_xref(name:"URL", value:"https://github.com/Hckwzh/cms/blob/main/17.md");
  script_xref(name:"URL", value:"https://github.com/Hckwzh/cms/blob/main/18.md");
  script_xref(name:"URL", value:"https://github.com/Hckwzh/cms/blob/main/19.md");
  script_xref(name:"URL", value:"https://github.com/Hckwzh/cms/blob/main/20.md");
  script_xref(name:"URL", value:"https://github.com/Hckwzh/cms/blob/main/21.md");
  script_xref(name:"URL", value:"https://github.com/Hckwzh/cms/blob/main/22.md");
  script_xref(name:"URL", value:"https://github.com/Hckwzh/cms/blob/main/23.md");
  script_xref(name:"URL", value:"https://github.com/Hckwzh/cms/blob/main/24.md");
  script_xref(name:"URL", value:"https://github.com/Hckwzh/cms/blob/main/25.md");
  script_xref(name:"URL", value:"https://vuldb.com/?id.263889");
  script_xref(name:"URL", value:"https://github.com/itsqian797/cms/blob/main/2.md");
  script_xref(name:"URL", value:"https://github.com/itsqian797/cms/blob/main/1.md");
  script_xref(name:"URL", value:"https://github.com/itsqian797/cms/blob/main/3.md");
  script_xref(name:"URL", value:"https://github.com/itsqian797/cms/blob/main/4.md");
  script_xref(name:"URL", value:"https://github.com/777erp/cms/blob/main/1.md");
  script_xref(name:"URL", value:"https://github.com/777erp/cms/blob/main/2.md");
  script_xref(name:"URL", value:"https://github.com/777erp/cms/blob/main/6.md");
  script_xref(name:"URL", value:"https://github.com/777erp/cms/blob/main/5.md");
  script_xref(name:"URL", value:"https://github.com/777erp/cms/blob/main/10.md");
  script_xref(name:"URL", value:"https://github.com/777erp/cms/blob/main/9.md");
  script_xref(name:"URL", value:"https://github.com/777erp/cms/blob/main/7.md");
  script_xref(name:"URL", value:"https://github.com/777erp/cms/blob/main/3.md");
  script_xref(name:"URL", value:"https://github.com/777erp/cms/blob/main/4.md");
  script_xref(name:"URL", value:"https://github.com/777erp/cms/blob/main/12.md");
  script_xref(name:"URL", value:"https://github.com/777erp/cms/blob/main/18.md");
  script_xref(name:"URL", value:"https://github.com/777erp/cms/blob/main/14.md");
  script_xref(name:"URL", value:"https://github.com/777erp/cms/blob/main/15.md");
  script_xref(name:"URL", value:"https://github.com/777erp/cms/blob/main/19.md");
  script_xref(name:"URL", value:"https://github.com/777erp/cms/blob/main/11.md");
  script_xref(name:"URL", value:"https://github.com/777erp/cms/blob/main/17.md");
  script_xref(name:"URL", value:"https://github.com/777erp/cms/blob/main/13.md");
  script_xref(name:"URL", value:"https://github.com/777erp/cms/blob/main/20.md");
  script_xref(name:"URL", value:"https://github.com/ysl1415926/cve/blob/main/CVE-2024-29660.md");
  script_xref(name:"URL", value:"https://github.com/iimiss/cms/blob/main/1.md");
  script_xref(name:"URL", value:"https://github.com/ysl1415926/cve/blob/main/DedeCMSv5.7_getshell.md");
  script_xref(name:"URL", value:"https://github.com/testgo1safe/cms/blob/main/1.md");
  script_xref(name:"URL", value:"https://github.com/Fishkey1/cms/blob/main/1.md");
  script_xref(name:"URL", value:"https://gitee.com/zchuanwen/cve/issues/I9HQRY");
  script_xref(name:"URL", value:"https://gitee.com/zchuanwen/cve123/issues/I9I18D");
  script_xref(name:"URL", value:"https://github.com/QianGeG/CVE/issues/13");
  script_xref(name:"URL", value:"https://vuldb.com/?id.263873");
  script_xref(name:"URL", value:"https://gist.github.com/Tsq741/a16015209fa8728d505c4f82b4f518cd");
  script_xref(name:"URL", value:"https://github.com/QianGeG/CVE/issues/14");
  script_xref(name:"URL", value:"https://gitee.com/fushuling/cve/blob/master/dedeCMS%20V5.7.114%20article_template_rand.php%20code%20injection.md");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "5.7.114" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 0 );
