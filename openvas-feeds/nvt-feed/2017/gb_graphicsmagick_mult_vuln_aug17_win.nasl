# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:graphicsmagick:graphicsmagick";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112027");
  script_version("2024-02-08T05:05:59+0000");
  script_cve_id("CVE-2017-11642", "CVE-2017-12935", "CVE-2017-12936", "CVE-2017-12937", "CVE-2017-13063", "CVE-2017-13064", "CVE-2017-13065", "CVE-2017-13066", "CVE-2017-13147", "CVE-2017-13148");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-03 15:15:00 +0000 (Tue, 03 Dec 2019)");
  script_tag(name:"creation_date", value:"2017-08-23 11:38:13 +0200 (Wed, 23 Aug 2017)");
  script_name("GraphicsMagick Multiple Vulnerabilities (Aug 2017) - Windows");

  script_tag(name:"summary", value:"GraphicsMagick is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"GraphicsMagick 1.3.26 and prior is prone to multiple vulnerabilities:

  - Allocation failure vulnerabilities.

  - Heap buffer overflow vulnerabilities.

  - Null pointer dereference vulnerabilities.

  - Memory leak vulnerabilities.

  - Invalid memory read vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause a denial of service via a crafted file.");

  script_tag(name:"affected", value:"GraphicsMagick version 1.3.26 and earlier on Windows");

  script_tag(name:"solution", value:"Updates are available, see the references for details.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://sourceforge.net/p/graphicsmagick/bugs/434/");
  script_xref(name:"URL", value:"https://sourceforge.net/p/graphicsmagick/bugs/436/");
  script_xref(name:"URL", value:"https://sourceforge.net/p/graphicsmagick/bugs/435/");
  script_xref(name:"URL", value:"https://sourceforge.net/p/graphicsmagick/bugs/430/");
  script_xref(name:"URL", value:"https://sourceforge.net/p/graphicsmagick/bugs/446/");
  script_xref(name:"URL", value:"https://blogs.gentoo.org/ago/2017/08/05/graphicsmagick-invalid-memory-read-in-setimagecolorcallback-image-c/");
  script_xref(name:"URL", value:"https://blogs.gentoo.org/ago/2017/08/05/graphicsmagick-use-after-free-in-readwmfimage-wmf-c/");
  script_xref(name:"URL", value:"https://blogs.gentoo.org/ago/2017/08/05/graphicsmagick-heap-based-buffer-overflow-in-readsunimage-sun-c/");

  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_graphicsmagick_detect_win.nasl");
  script_mandatory_keys("GraphicsMagick/Win/Installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!gmVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less_equal(version:gmVer, test_version:"1.3.26"))
{
  report = report_fixed_ver(installed_version:gmVer, fixed_version:"See Vendor");
  security_message(data:report);
  exit(0);
}
