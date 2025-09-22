# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.1288.1");
  script_cve_id("CVE-2018-1000041");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-02 16:19:18 +0000 (Fri, 02 Mar 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:1288-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:1288-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20181288-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083232");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-May/004049.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'librsvg' package(s) announced via the SUSE-SU-2018:1288-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for librsvg fixes the following issues:

- CVE-2018-1000041: Input validation issue could lead to credentials leak. (bsc#1083232)

Update to version 2.40.20:

 + Except for emergencies, this will be the LAST RELEASE of the
 librsvg-2.40.x series. We are moving to 2.41, which is vastly
 improved over the 2.40 series. The API/ABI there remain unchaged,
 so we strongly encourage you to upgrade your sources and binaries to
 librsvg-2.41.x.
 + bgo#761175 - Allow masks and clips to reuse a node being drawn.
 + Don't access the file system when deciding whether to load a remote
 file with a UNC path for a paint server (i.e. don't try to load it at all).
 + Vistual Studio: fixed and integrated introspection builds, so
 introspection data is built directly from the Visual Studio project
 (Chun-wei Fan).
 + Visual Studio: We now use HIGHENTROPYVA linker option on x64 builds,
 to enhance the security of built binaries (Chun-wei Fan).
 + Fix generation of Vala bindings when compiling in read-only source
 directories (Emmanuele Bassi).

Update to version 2.40.19:

 + bgo#621088: Using text objects as clipping paths is now supported.
 + bgo#587721: Fix rendering of text elements with transformations (Massimo).
 + bgo#777833 - Fix memory leaks when an RsvgHandle is disposed before
 being closed (Philip Withnall).
 + bgo#782098 - Don't pass deprecated options to gtk-doc (Ting-Wei Lan).
 + bgo#786372 - Fix the default for the 'type' attribute of the <style> element.
 + bgo#785276 - Don't crash on single-byte files.
 + bgo#634514: Don't render unknown elements and their sub-elements.
 + bgo#777155 - Ignore patterns that have close-to-zero dimensions.
 + bgo#634324 - Fix Gaussian blurs with negative scaling.
 + Fix the <switch> element, it wasn't working at all.
 + Fix loading when rsvg_handle_write() is called one byte at a time.
 + bgo#787895 - Fix incorrect usage of libxml2. Thanks to Nick Wellnhofer
 for advice on this.
 + Backported the test suite machinery from the master branch (Chun-wei Fan,
 Federico Mena).
 + We now require Pango 1.38.0 or later (released in 2015).
 + We now require libxml2 2.9.0 or later (released in 2012).");

  script_tag(name:"affected", value:"'librsvg' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-loader-rsvg", rpm:"gdk-pixbuf-loader-rsvg~2.40.20~5.6.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librsvg-2-2", rpm:"librsvg-2-2~2.40.20~5.6.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librsvg-2-2-32bit", rpm:"librsvg-2-2-32bit~2.40.20~5.6.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsvg-view", rpm:"rsvg-view~2.40.20~5.6.1", rls:"SLES12.0SP3"))) {
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
