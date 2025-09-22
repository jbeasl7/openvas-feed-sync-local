# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108934");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2020-10-05 10:39:51 +0000 (Mon, 05 Oct 2020)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Western Digital My Cloud Products End of Life (EOL) Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("General");
  script_dependencies("gb_wd_mycloud_consolidation.nasl");
  script_mandatory_keys("wd-mycloud/detected");

  script_xref(name:"URL", value:"https://support-en.wd.com/app/answers/detail/a_id/28740");

  script_tag(name:"summary", value:"The remote Western Digital My Cloud device has reached the End of Life
  (EOL) / End of Updates (EOU) and should not be used anymore.");

  script_tag(name:"impact", value:"An EOL / EOU My Cloud device is not receiving any security updates from
  the vendor. Unfixed security vulnerabilities might be leveraged by an attacker to compromise the
  security of this host.");

  script_tag(name:"solution", value:"Replace the device by a still supported one.");

  script_tag(name:"vuldetect", value:"Checks if the target host is a My Cloud device which has reached
  the EOL / EOU.");

  exit(0);
}

include("host_details.inc");
include("eol_shared.inc");

cpe_list = make_list("cpe:/o:wdc:my_cloud_firmware",
                     # nb: Commented out as it is currently not clear if / how the My Cloud Mirror
                     # in  Gen 2 (which is still supported) is currently detected by the Detection-VT.
                     # "cpe:/o:wdc:my_cloud_mirror_firmware",
                     "cpe:/o:wdc:my_cloud_ex2_firmware",
                     "cpe:/o:wdc:my_cloud_ex4_firmware",
                     "cpe:/o:wdc:my_cloud_ex2100_firmware",
                     "cpe:/o:wdc:my_cloud_dl2100_firmware",
                     "cpe:/o:wdc:my_cloud_dl4100_firmware");

# End of Updates is always "Last Manufactured Date" + 4 years (See https://support-en.wd.com/app/answers/detail/a_id/28740)
prod_date_arr = make_array("cpe:/o:wdc:my_cloud_firmware", "2020-06-30",
                           "cpe:/o:wdc:my_cloud_mirror_firmware", "2019-12-31",
                           "cpe:/o:wdc:my_cloud_ex2_firmware", "2020-03-31",
                           "cpe:/o:wdc:my_cloud_ex4_firmware", "2020-03-31",
                           "cpe:/o:wdc:my_cloud_ex2100_firmware", "2019-12-31",
                           "cpe:/o:wdc:my_cloud_dl2100_firmware", "2020-03-31",
                           "cpe:/o:wdc:my_cloud_dl4100_firmware", "2020-03-31");

if (!infos = get_app_location_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];

if (!prod_date_arr[cpe])
  exit(0);

# nb: Only devices running v3/4.x are currently EOL.
if (cpe == "cpe:/o:wdc:my_cloud_firmware") {
  version = get_app_version(cpe: cpe, nofork: TRUE);
  if (version && version =~ "^0?[34]\.")
    vuln = TRUE;
} else {
  vuln = TRUE;
}

if (vuln) {
  report = eol_build_message(name: "Western Digital My Cloud",
                             cpe: cpe,
                             eol_date: prod_date_arr[cpe],
                             eol_url: "https://support-en.wd.com/app/answers/detail/a_id/28740",
                             eol_type: "prod",
                             skip_version: TRUE);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
