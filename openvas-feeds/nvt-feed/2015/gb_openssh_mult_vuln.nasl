# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openbsd:openssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806052");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-6564", "CVE-2015-6563", "CVE-2015-5600");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-09-15 10:17:32 +0530 (Tue, 15 Sep 2015)");
  script_name("OpenSSH Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("General");
  script_dependencies("gb_openssh_consolidation.nasl");
  script_mandatory_keys("openssh/detected");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Aug/54");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/07/23/4");

  script_tag(name:"summary", value:"OpenSSH is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Use-after-free vulnerability in the 'mm_answer_pam_free_ctx' function in
  monitor.c in sshd.

  - Vulnerability in 'kbdint_next_device' function in auth2-chall.c in sshd.

  - Vulnerability in the handler for the MONITOR_REQ_PAM_FREE_CTX request.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to gain privileges, to conduct impersonation attacks, to conduct brute-force
  attacks or cause a denial of service.");

  script_tag(name:"affected", value:"OpenSSH versions before 7.0.");

  script_tag(name:"solution", value:"Upgrade to OpenSSH 7.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"7.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"7.0", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );