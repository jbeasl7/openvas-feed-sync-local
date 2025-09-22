# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.90014");
  script_version("2025-06-04T05:40:50+0000");
  script_tag(name:"last_modification", value:"2025-06-04 05:40:50 +0000 (Wed, 04 Jun 2025)");
  script_tag(name:"creation_date", value:"2008-06-17 20:22:38 +0200 (Tue, 17 Jun 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-1238", "CVE-2008-1240", "CVE-2008-1241", "CVE-2008-0412",
                "CVE-2008-0416");
  script_name("Mozilla Firefox, Thunderbird, Seamonkey: Multiple Vulnerabilities (MFSA2008-14) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("General");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2008-14/");

  script_tag(name:"summary", value:"Mozilla Firefox, Thunderbird and Seamonkey are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Mozilla contributors moz_bug_r_a4, Boris Zbarsky, and Johnny
  Stenback reported a series of vulnerabilities which allow scripts from page content to run with
  elevated privileges. moz_bug_r_a4 demonstrated additional variants of MFSA2007-25 and MFSA2007-35
  (arbitrary code execution through XPCNativeWrapper pollution). Additional vulnerabilities reported
  separately by Boris Zbarsky, Johnny Stenback, and moz_bug_r_a4 showed that the browser could be
  forced to run JavaScript code using the wrong principal leading to universal XSS and arbitrary
  code execution.");

  script_tag(name:"solution", value:"All Users should upgrade to the latest versions of Firefox,
  Thunderbird or Seamonkey.");

  script_tag(name:"deprecated", value:TRUE); # This VT is broken in many ways...

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

exit(66);
