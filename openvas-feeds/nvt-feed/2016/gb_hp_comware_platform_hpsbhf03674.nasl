# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:hp:comware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106460");
  script_version("2025-09-09T14:09:45+0000");
  script_tag(name:"last_modification", value:"2025-09-09 14:09:45 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-12-09 13:42:32 +0700 (Fri, 09 Dec 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-28 11:27:00 +0000 (Thu, 28 Jul 2022)");

  script_cve_id("CVE-2016-2183");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("HPE Comware Network Products Remote Information Disclosure Vulnerability (HPSBHF03674)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_hp_comware_platform_snmp_detect.nasl",
                      "gb_hp_comware_platform_ssh_banner_detect.nasl",
                      "gb_ssl_tls_ciphers_gathering.nasl");
  script_mandatory_keys("hp/comware_device", "ssl_tls/port",
                        "ssl_tls/ciphers/supported_ciphers");

  script_tag(name:"summary", value:"HPE Comware 5 and Comware 7 network products are prone to an information
  disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if DES and 3DES ciphers are enabled on the SSL ports.");

  script_tag(name:"insight", value:"A potential security vulnerability in the DES/3DES block ciphers could
  potentially impact HPE Comware 5 and Comware 7 network products using SSL/TLS.");

  script_tag(name:"impact", value:"This vulnerability could be exploited remotely resulting in disclosure of
  information.");

  script_tag(name:"affected", value:"Comware 5 and Comware 7 Products: All versions");

  script_tag(name:"solution", value:"For mitigation HPE recommends disabling DES and 3DES ciphers.");

  script_xref(name:"URL", value:"https://support.hpe.com/hpesc/public/docDisplay?docId=c05349499&docLocale=en_US");

  exit(0);
}

include("host_details.inc");
include("ssl_funcs.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version =~ "^[57]") {
  port = tls_ssl_get_port();
  if (!port)
    exit(0);

  weakciphers = get_kb_list("ssl_tls/ciphers/*/" + port + "/supported_ciphers");
  if (weakciphers =~ "_3?DES_") {
    security_message(port: port);
    exit(0);
  }
}

exit(0);
