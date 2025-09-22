# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802924");
  script_version("2024-02-20T14:37:13+0000");
  script_cve_id("CVE-2011-3426", "CVE-2011-3016", "CVE-2011-3021", "CVE-2011-3027",
                "CVE-2011-3032", "CVE-2011-3034", "CVE-2011-3035", "CVE-2011-3036",
                "CVE-2011-3037", "CVE-2011-3038", "CVE-2011-3039", "CVE-2011-3040",
                "CVE-2011-3041", "CVE-2011-3042", "CVE-2011-3043", "CVE-2011-3044",
                "CVE-2011-3050", "CVE-2011-3053", "CVE-2011-3059", "CVE-2011-3060",
                "CVE-2011-3064", "CVE-2011-3068", "CVE-2011-3069", "CVE-2011-3071",
                "CVE-2011-3073", "CVE-2011-3074", "CVE-2011-3075", "CVE-2011-3076",
                "CVE-2011-3078", "CVE-2011-3081", "CVE-2011-3086", "CVE-2011-3089",
                "CVE-2011-3090", "CVE-2011-3913", "CVE-2011-3924", "CVE-2011-3926",
                "CVE-2011-3958", "CVE-2011-3966", "CVE-2011-3968", "CVE-2011-3969",
                "CVE-2011-3971", "CVE-2011-3067", "CVE-2011-2845", "CVE-2012-0678",
                "CVE-2012-0679", "CVE-2012-0680", "CVE-2012-0682", "CVE-2012-0683",
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
                "CVE-2012-3650");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-20 14:37:13 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-07-30 16:35:41 +0530 (Mon, 30 Jul 2012)");
  script_name("Apple Safari Multiple Vulnerabilities (Jul 2012) - Mac OS X");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT5400");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50124");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50360");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51041");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51641");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51911");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52031");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52271");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52674");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52762");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52913");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53309");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53540");
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
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2012/Jul/msg00000.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to disclose potentially
  sensitive information, conduct cross-site scripting and compromise a user's system.");

  script_tag(name:"affected", value:"Apple Safari versions prior to 6.0.");

  script_tag(name:"insight", value:"Please see the references for more details about the vulnerabilities.");

  script_tag(name:"solution", value:"Upgrade to Apple Safari version 6.0 or later.");

  script_tag(name:"summary", value:"Apple Safari web browser is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName || "Mac OS X" >!< osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer)
  exit(0);

if(version_is_equal(version:osVer, test_version:"10.7.4")) {

  if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
    exit(0);

  vers = infos["version"];
  path = infos["location"];

  if(version_is_less(version:vers, test_version:"6.0")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"6.0", install_path:path);
    security_message(port:0, data:report);
    exit(0);
  }
  exit(99);
}

exit(0);
