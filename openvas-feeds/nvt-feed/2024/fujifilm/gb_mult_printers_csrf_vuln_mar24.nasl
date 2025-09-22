# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170785");
  script_version("2024-05-16T05:05:35+0000");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"creation_date", value:"2024-05-14 19:08:11 +0000 (Tue, 14 May 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");

  script_cve_id("CVE-2024-27974");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Fuji Xerox / Fujifilm Printers CSRF Vulnerability (Mar 2024)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_fujifilm_printer_consolidation.nasl");
  script_mandatory_keys("fujifilm/printer/detected");

  script_tag(name:"summary", value:"Multiple Fuji Xerox / Fujifilm printers are prone to cross-site request
  forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable firmware version is present on the target host.");

  script_tag(name:"insight", value:"Cross-site request forgery vulnerability in FUJIFILM printers which
  implement CentreWare Internet Services or Internet Services allows a remote unauthenticated attacker to
  alter user information. In the case the user is an administrator, the settings such as the administrator's
  ID, password, etc. may be altered.");

  script_tag(name:"solution", value:"To mitigate this vulnerability the vendor recommends to disable the
  CentreWare Internet Services or Internet Services functionality. See the referenced vendor advisory
  for details.

  Note: Please create an override for this result if the mitigations have been applied and/or the
  risk has been assessed and accepted.");

  script_xref(name:"URL", value:"https://www.fujifilm.com/fbglobal/eng/company/news/notice/2024/0306_1_announce.html");
  script_xref(name:"URL", value:"https://jvn.jp/en/jp/JVN34328023/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:fujifilm:docuprint_p455_d_firmware",
                     "cpe:/o:fujifilm:docuprint_m455_df_firmware",
                     "cpe:/o:fujifilm:docuprint_c2255_firmware",
                     "cpe:/o:fujifilm:docucentre-iv_c2260_firmware",
                     "cpe:/o:fujifilm:docucentre-iv_c2270_firmware",
                     "cpe:/o:fujifilm:docucentre-iv_c3370_firmware",
                     "cpe:/o:fujifilm:docucentre-iv_c4470_firmware",
                     "cpe:/o:fujifilm:docucentre-iv_c5570_firmware",
                     "cpe:/o:fujifilm:apeosport-iv_c2270_firmware",
                     "cpe:/o:fujifilm:apeosport-iv_c3370_firmware",
                     "cpe:/o:fujifilm:apeosport-iv_c4470_firmware",
                     "cpe:/o:fujifilm:apeosport-iv_c5570_firmware",
                     "cpe:/o:fujifilm:apeosport-iv_c2270_r_firmware",
                     "cpe:/o:fujifilm:apeosport-iv_c3370_r_firmware",
                     "cpe:/o:fujifilm:apeosport-iv_c4470_r_firmware",
                     "cpe:/o:fujifilm:apeosport-iv_c5570_r_firmware",
                     "cpe:/o:fujifilm:apeoswide_6050%2f3030_firmware",
                     "cpe:/o:fujifilm:apeoswide_6057%2f3037_firmware",
                     "cpe:/o:fujifilm:docuwide_6055_firmware",
                     "cpe:/o:fujifilm:docuwide_3035_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

version = infos["version"];

report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
security_message(port: 0, data: report);
exit(0);
