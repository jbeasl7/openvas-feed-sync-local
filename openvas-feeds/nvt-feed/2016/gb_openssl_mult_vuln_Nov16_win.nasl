# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107080");
  script_version("2024-02-08T05:05:59+0000");
  script_cve_id("CVE-2016-7054", "CVE-2016-7053");

  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-03 01:29:00 +0000 (Sun, 03 Sep 2017)");
  script_tag(name:"creation_date", value:"2016-11-11 11:19:11 +0100 (Fri, 11 Nov 2016)");
  script_tag(name:"qod_type", value:"remote_banner");

  script_name("OpenSSL Multiple Vulnerabilities (Nov 2016) - Windows");

  script_tag(name:"summary", value:"OpenSSL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  1. TLS connections using *-CHACHA20-POLY1305 ciphersuites are susceptible to a DoS attack by corrupting larger payloads. This can result in an OpenSSL crash.

  2. Applications parsing invalid CMS structures can crash with a NULL pointer dereference.
  This is caused  by a bug in the handling of the ASN.1 CHOICE type in OpenSSL 1.1.0 which can result in a NULL value being
  passed to the structure callback if an attempt is made to free certain invalid encodings. Only CHOICE structures
  using a callback which do not handle NULL value are affected.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a denial of service.");

  script_tag(name:"affected", value:"OpenSSL 1.1.0 versions prior to 1.1.0c");

  script_tag(name:"solution", value:"OpenSSL 1.1.0 users should upgrade to 1.1.0c.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20161110.txt");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_windows");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^1\.1\.0" && version_is_less(version:vers, test_version:"1.1.0c")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.1.0c", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
