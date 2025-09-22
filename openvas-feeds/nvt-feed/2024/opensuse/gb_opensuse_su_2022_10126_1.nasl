# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833117");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2018-25032", "CVE-2021-4216");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-30 18:50:40 +0000 (Wed, 30 Mar 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 07:13:06 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for mupdf (openSUSE-SU-2022:10126-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:10126-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/3URMJJJ2MKM4FNDYFMSSIEJDTNENDZRU");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mupdf'
  package(s) announced via the openSUSE-SU-2022:10126-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for mupdf fixes the following issues:
  mupdf was updated to 1.20.3:

  * return error, not success when unable to lock native device resource.

  * Bug 705620: Start journal operation instead of pushing local xref.

  * Ensure AndroidDrawDevice is destroyed, even upon exception.

  * source/pdf/pdf-clean.c: fix segv from incorrect call to fz_drop_pixmap().

  * Bug 705681: Enclose code in begin/end operation.

  * Guard against SEGVs when calling archive functions with NULL archive.
  mupdf was updated to 1.20.0 (boo#1202858, CVE-2021-4216):

  * Experimental C# bindings

  * Cross compilation should no longer need a host compiler

  * Major additions to JNI bindings

  * New API to edit outline

  * New API to resolve and create links

  * New API to toggle individual layers in PDF

  * Layer panel in mupdf-gl

  * Layer option in mutool draw

  * New API to add a Javascript console

  * Console panel in mupdf-gl

  * Text search API extended to be able to distinguish between separate
       search hits

  * Command line tool improvements:

  * all: Negative page numbers to index from the last page

  * mutool draw: Add option to render document without text

  * mutool draw and convert: Support DPI option in text and HTML output

  * New hybrid HTML output format using 'scripts/pdftohtml' script:

  * Graphics in a background image

  * Text on top

  * Improved WASM viewer demo

  * Support high DPI screens

  * Progressive loading

  * Update to zlib 1.2.12 for security fix
  mupdf was updated to 1.19.1:

  * Updated zlib to 1.2.12 due to CVE-2018-25032");

  script_tag(name:"affected", value:"'mupdf' package(s) on openSUSE Backports SLE-15-SP4.");

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

if(release == "openSUSEBackportsSLE-15-SP4") {

  if(!isnull(res = isrpmvuln(pkg:"mupdf", rpm:"mupdf~1.20.3~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mupdf-devel-static", rpm:"mupdf-devel-static~1.20.3~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mupdf", rpm:"mupdf~1.20.3~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mupdf-devel-static", rpm:"mupdf-devel-static~1.20.3~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
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