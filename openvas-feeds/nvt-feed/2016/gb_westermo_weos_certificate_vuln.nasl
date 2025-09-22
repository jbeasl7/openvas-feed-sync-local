# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:westermo:weos";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106197");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"creation_date", value:"2016-08-24 11:49:27 +0700 (Wed, 24 Aug 2016)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-03-07 16:35:00 +0000 (Mon, 07 Mar 2016)");

  script_cve_id("CVE-2015-7923");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Westermo WeOS < 4.19.0 Hard-coded Certificate Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_westermo_weos_snmp_detect.nasl");
  script_mandatory_keys("westermo/weos/detected");

  script_tag(name:"summary", value:"Westermo WeOS uses the same SSL private key across different
  customers installations.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The SSL keys used by the switches to provide secure
  communications are hard coded. Malicious parties could obtain the key, stage a Man-in-the-Middle
  attack posing to be a WeOS device, and then obtain credentials entered by the end-user. With
  those credentials, the malicious party would have authenticated access to that device.");

  script_tag(name:"impact", value:"Certificates provide a key used by the switch software to
  encrypt and decrypt communications. The detrimental impact of the certificate being hard coded is
  that the key cannot be changed. Once the key is compromised, a malicious party has access to the
  decrypted network traffic from the device. A malicious party can then read and modify traffic
  that is intercepted and decrypted.");

  script_tag(name:"affected", value:"Westermo WeOS prior to version 4.19.0.");

  script_tag(name:"solution", value:"Westermo has released a patch that allows changing default
  certificates to custom certificates.");

  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-16-028-01");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "4.19.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "Contact the vendor");
  security_message(port: port, data: report, proto: "udp");
  exit(0);
}

exit(99);
