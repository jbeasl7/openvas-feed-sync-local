# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.851478");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2017-01-18 05:46:30 +0100 (Wed, 18 Jan 2017)");
  script_cve_id("CVE-2016-7445", "CVE-2016-8332", "CVE-2016-9112", "CVE-2016-9113",
                "CVE-2016-9114", "CVE-2016-9115", "CVE-2016-9116", "CVE-2016-9117",
                "CVE-2016-9118", "CVE-2016-9572", "CVE-2016-9573", "CVE-2016-9580",
                "CVE-2016-9581");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-09 19:57:00 +0000 (Wed, 09 Sep 2020)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for openjpeg2 (openSUSE-SU-2017:0185-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjpeg2'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openjpeg2 fixes the following issues:

  * CVE-2016-9572 CVE-2016-9573: Insufficient check in imagetopnm() could
  lead to heap buffer overflow [bsc#1014543]

  * CVE-2016-9580, CVE-2016-9581: Possible Heap buffer overflow via integer
  overflow and infinite loop [bsc#1014975]

  * CVE-2016-7445: Null pointer dereference in convert.c could lead to crash
  [bsc#999817]

  * CVE-2016-8332: Malicious file in OpenJPEG JPEG2000 format  could lead to
  code execution [bsc#1002414]

  * CVE-2016-9112: FPE(Floating Point Exception) in lib/openjp2/pi.c:523
  [bsc#1007747]

  * CVE-2016-9113: NULL point dereference in function imagetobmp of
  convertbmp.c could lead to crash [bsc#1007739]

  * CVE-2016-9114: NULL Pointer Access in function imagetopnm of
  convert.c:1943(jp2) could lead to crash [bsc#1007740]

  * CVE-2016-9115: Heap Buffer Overflow in function imagetotga of
  convert.c(jp2) [bsc#1007741]

  * CVE-2016-9116: NULL Pointer Access in function imagetopnm of
  convert.c:2226(jp2) [bsc#1007742]

  * CVE-2016-9117: NULL Pointer Access in function imagetopnm of
  convert.c(jp2):1289 [bsc#1007743]

  * CVE-2016-9118: Heap Buffer Overflow in function pnmtoimage of convert.c
  [bsc#1007744]");

  script_tag(name:"affected", value:"openjpeg2 on openSUSE 13.2");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2017:0185-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSE13.2")
{

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2-7", rpm:"libopenjp2-7~2.1.0~2.3.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2-7-debuginfo", rpm:"libopenjp2-7-debuginfo~2.1.0~2.3.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2", rpm:"openjpeg2~2.1.0~2.3.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2-debuginfo", rpm:"openjpeg2-debuginfo~2.1.0~2.3.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2-debugsource", rpm:"openjpeg2-debugsource~2.1.0~2.3.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2-devel", rpm:"openjpeg2-devel~2.1.0~2.3.1", rls:"openSUSE13.2"))) {
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
