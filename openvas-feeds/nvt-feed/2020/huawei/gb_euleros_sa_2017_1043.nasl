# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2017.1043");
  script_cve_id("CVE-2014-8127", "CVE-2014-8129", "CVE-2014-8130", "CVE-2014-9330", "CVE-2014-9655", "CVE-2015-1547", "CVE-2015-7554", "CVE-2015-8665", "CVE-2015-8668", "CVE-2015-8683", "CVE-2015-8781", "CVE-2015-8784", "CVE-2016-3632", "CVE-2016-3945", "CVE-2016-3990", "CVE-2016-3991", "CVE-2016-5652", "CVE-2016-9533", "CVE-2016-9534", "CVE-2016-9535", "CVE-2016-9536", "CVE-2016-9537", "CVE-2016-9540");
  script_tag(name:"creation_date", value:"2020-01-23 10:45:35 +0000 (Thu, 23 Jan 2020)");
  script_version("2025-02-13T05:37:41+0000");
  script_tag(name:"last_modification", value:"2025-02-13 05:37:41 +0000 (Thu, 13 Feb 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-23 16:00:43 +0000 (Wed, 23 Nov 2016)");

  script_name("Huawei EulerOS: Security Advisory for compat-libtiff3 (EulerOS-SA-2017-1043)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2017-1043");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2017-1043");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'compat-libtiff3' package(s) announced via the EulerOS-SA-2017-1043 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The (1) putcontig8bitYCbCr21tile function in tif_getimage.c or (2) NeXTDecode function in tif_next.c in LibTIFF allows remote attackers to cause a denial of service (uninitialized memory access) via a crafted TIFF image, as demonstrated by libtiff-cvs-1.tif and libtiff-cvs-2.tif.(CVE-2014-8127,CVE-2014-8129,CVE-2014-8130,CVE-2014-9655)

A flaw was discovered in the bmp2tiff utility. By tricking a user into processing a specially crafted file, a remote attacker could exploit this flaw to cause a crash or memory corruption and, possibly, execute arbitrary code with the privileges of the user running the libtiff tool.(CVE-2014-9330,CVE-2015-7554,CVE-2015-8668,CVE-2015-8665,CVE-2015-8781,CVE-2016-3632,CVE-2016-3945,CVE-2016-3990,CVE-2016-3991,CVE-2016-5652,CVE-2015-8683)

tools/tiffcp.c in libtiff has an out-of-bounds write on tiled images with odd tile width versus image width. Reported as MSVR 35103, aka 'cpStripToTile heap-buffer-overflow.'(CVE-2016-9540)

tif_predict.h and tif_predict.c in libtiff have assertions that can lead to assertion failures in debug mode, or buffer overflows in release mode, when dealing with unusual tile size like YCbCr with subsampling. Reported as MSVR 35105, aka 'Predictor heap-buffer-overflow.'(CVE-2016-9535,CVE-2016-9533,CVE-2016-9534,CVE-2016-9536,CVE-2016-9537)

The NeXTDecode function in tif_next.c in LibTIFF allows remote attackers to cause a denial of service (uninitialized memory access) via a crafted TIFF image, as demonstrated by libtiff5.tif.(CVE-2015-1547)

The NeXTDecode function in tif_next.c in LibTIFF allows remote attackers to cause a denial of service (out-of-bounds write) via a crafted TIFF image, as demonstrated by libtiff5.tif.(CVE-2015-8784)");

  script_tag(name:"affected", value:"'compat-libtiff3' package(s) on Huawei EulerOS V2.0SP2.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "EULEROS-2.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"compat-libtiff3", rpm:"compat-libtiff3~3.9.4~11.h19", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
