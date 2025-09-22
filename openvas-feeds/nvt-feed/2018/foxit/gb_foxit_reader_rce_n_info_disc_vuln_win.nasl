# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:foxitsoftware:reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814065");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2018-17607", "CVE-2018-17608", "CVE-2018-17609", "CVE-2018-17610",
                "CVE-2018-17611", "CVE-2018-17781", "CVE-2018-16291", "CVE-2018-16292",
                "CVE-2018-16293", "CVE-2018-16294", "CVE-2018-16295", "CVE-2018-16296",
                "CVE-2018-16297", "CVE-2018-3940", "CVE-2018-3941", "CVE-2018-3942",
                "CVE-2018-3943", "CVE-2018-3944", "CVE-2018-3945", "CVE-2018-3946",
                "CVE-2018-3957", "CVE-2018-3958", "CVE-2018-3962", "CVE-2018-3992",
                "CVE-2018-3993", "CVE-2018-3994", "CVE-2018-3995", "CVE-2018-3996",
                "CVE-2018-3997");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-14 17:37:00 +0000 (Wed, 14 Nov 2018)");
  script_tag(name:"creation_date", value:"2018-10-03 11:59:56 +0530 (Wed, 03 Oct 2018)");
  script_name("Foxit Reader < 9.3 Multiple Vulnerabilities - Windows");

  script_tag(name:"summary", value:"Foxit Reader is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  A remote user can:

  - cause arbitrary code to be executed on the target user's system.

  - cause the target user's application to crash. A remote user can obtain potentially sensitive information on the target system.

  - cause a use-after-free memory error by causing a dialog box to pop open repeatedly.

  - cause a use-after-free memory error by using objects that have been deleted or closed.

  - cause a use-after-free memory error using a control object after it has been deleted within a static XFA layout or using a wild pointer resulting from a deleted object after XFA re-layout.

  - cause a use-after-free memory error when processing certain properties of Annotation objects by using freed objects.

  - cause a use-after-free memory error or crash when processing PDF documents or certain properties of a PDF form.

  - cause an uninitialized object information disclosure when creating ArrayBuffer and DataView objects [CVE-2018-17781].

  - cause a memory corruption error when getting a pageIndex object without an initial value [CVE-2018-3992].

  - cause an out-of-bounds memory read error when processing the Lower () method of a XFA object.

  - trigger a type confusion error when using a null pointer without validation.

  - cause an out-of-bounds memory read error and crash when parsing certain BMP images due to the access of an invalid address.

  - cause an out-of-bounds memory read error when processing a PDF file that contains non-standard signatures.

  Furthermore:

  - An out-of-bounds memory read/write error may occur when parsing non-integer strings when converting HTML files to PDF files.

  - A use-after-free memory error may occur when parsing non-integer strings when converting HTML files to PDF files.

  - An out-of-bounds memory read error or use-after-free code execution error may occur when executing certain JavaScript due to the use of the document and auxiliary objects.

  - The creation of ArrayBuffer and DataView objects is mishandled.

  - The properties of Annotation objects are mishandled.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code or cause a denial of service (use-after-free)
  and disclose sensitive information.");

  script_tag(name:"affected", value:"Foxit Reader versions before 9.3.");

  script_tag(name:"solution", value:"Update to version 9.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_xref(name:"URL", value:"https://securitytracker.com/id/1041769");

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_foxit_reader_detect_portable_win.nasl");
  script_mandatory_keys("foxit/reader/ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"9.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"9.3", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);