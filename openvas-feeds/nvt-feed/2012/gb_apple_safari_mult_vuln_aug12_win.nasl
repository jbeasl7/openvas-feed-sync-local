# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802925");
  script_version("2025-09-16T05:38:45+0000");
  script_cve_id("CVE-2012-0678", "CVE-2012-0679", "CVE-2012-0680", "CVE-2012-0682",
                "CVE-2012-1520", "CVE-2012-1521", "CVE-2012-3589", "CVE-2012-3590",
                "CVE-2012-3591", "CVE-2012-3592", "CVE-2012-3593", "CVE-2012-3594",
                "CVE-2012-3595", "CVE-2012-3596", "CVE-2012-3597", "CVE-2012-3599",
                "CVE-2012-3600", "CVE-2012-3603", "CVE-2012-3604", "CVE-2012-3605",
                "CVE-2012-3608", "CVE-2012-3609", "CVE-2012-3610", "CVE-2012-3611",
                "CVE-2012-3615", "CVE-2012-3618", "CVE-2012-3620", "CVE-2012-3625",
                "CVE-2012-3626", "CVE-2012-3627", "CVE-2012-3628", "CVE-2012-3629",
                "CVE-2012-3630", "CVE-2012-3631", "CVE-2012-3633", "CVE-2012-3634",
                "CVE-2012-3635", "CVE-2012-3636", "CVE-2012-3637", "CVE-2012-3638",
                "CVE-2012-3639", "CVE-2012-3640", "CVE-2012-3641", "CVE-2012-3642",
                "CVE-2012-3644", "CVE-2012-3645", "CVE-2012-3646", "CVE-2012-3653",
                "CVE-2012-3655", "CVE-2012-3656", "CVE-2012-3661", "CVE-2012-3663",
                "CVE-2012-3664", "CVE-2012-3665", "CVE-2012-3666", "CVE-2012-3667",
                "CVE-2012-3668", "CVE-2012-3669", "CVE-2012-3670", "CVE-2012-3674",
                "CVE-2012-3678", "CVE-2012-3679", "CVE-2012-3680", "CVE-2012-3681",
                "CVE-2012-3682", "CVE-2012-3683", "CVE-2012-3686", "CVE-2012-3689",
                "CVE-2012-3690", "CVE-2012-3691", "CVE-2012-2815", "CVE-2012-3693",
                "CVE-2012-3694", "CVE-2012-3695", "CVE-2012-3696", "CVE-2012-3697",
                "CVE-2012-3650", "CVE-2012-0683");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"creation_date", value:"2012-08-01 10:16:52 +0530 (Wed, 01 Aug 2012)");
  script_name("Apple Safari Multiple Vulnerabilities (HT5400) - Windows");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/103354");
  script_xref(name:"URL", value:"https://lists.apple.com/archives/security-announce/2012/Jul/msg00000.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54203");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54680");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54683");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54686");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54687");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54688");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54692");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54693");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54694");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54695");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54696");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54697");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54700");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54703");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50058/");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1027307");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("gb_apple_safari_smb_login_detect.nasl");
  script_mandatory_keys("apple/safari/smb-login/detected");

  script_tag(name:"summary", value:"Apple Safari is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Please see the references for more information on the
  vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to disclose
  potentially sensitive information, conduct cross-site scripting and compromise a user's system.");

  script_tag(name:"affected", value:"Apple Safari versions 5.1.7 and prior.");

  # nb: Seems to be only fixed on 6.1 but 5.x was the last version on Windows
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"5.34.57.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"None", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
