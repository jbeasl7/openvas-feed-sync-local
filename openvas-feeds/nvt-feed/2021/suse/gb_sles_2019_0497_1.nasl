# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.0497.1");
  script_cve_id("CVE-2018-4437", "CVE-2018-4438", "CVE-2018-4441", "CVE-2018-4442", "CVE-2018-4443", "CVE-2018-4464", "CVE-2019-6212", "CVE-2019-6215", "CVE-2019-6216", "CVE-2019-6217", "CVE-2019-6226", "CVE-2019-6227", "CVE-2019-6229", "CVE-2019-6233", "CVE-2019-6234");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:30 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-06 15:32:41 +0000 (Wed, 06 Mar 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:0497-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:0497-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20190497-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2gtk3' package(s) announced via the SUSE-SU-2019:0497-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for webkit2gtk3 to version 2.22.6 fixes the following issues
(boo#1124937 boo#1119558):

Security vulnerabilities fixed:
CVE-2018-4437: Processing maliciously crafted web content may lead to
 arbitrary code execution. Multiple memory corruption issues were
 addressed with improved memory handling. (boo#1119553)

CVE-2018-4438: Processing maliciously crafted web content may lead to
 arbitrary code execution. A logic issue existed resulting in memory
 corruption. This was addressed with improved state management.
 (boo#1119554)

CVE-2018-4441: Processing maliciously crafted web content may lead to
 arbitrary code execution. A memory corruption issue was addressed with
 improved memory handling. (boo#1119555)

CVE-2018-4442: Processing maliciously crafted web content may lead to
 arbitrary code execution. A memory corruption issue was addressed with
 improved memory handling. (boo#1119556)

CVE-2018-4443: Processing maliciously crafted web content may lead to
 arbitrary code execution. A memory corruption issue was addressed with
 improved memory handling. (boo#1119557)

CVE-2018-4464: Processing maliciously crafted web content may lead to
 arbitrary code execution. Multiple memory corruption issues were
 addressed with improved memory handling. (boo#1119558)

CVE-2019-6212: Processing maliciously crafted web content may lead to
 arbitrary code execution. Multiple memory corruption issues were
 addressed with improved memory handling.

CVE-2019-6215: Processing maliciously crafted web content may lead to
 arbitrary code execution. A type confusion issue was addressed with
 improved memory handling.

CVE-2019-6216: Processing maliciously crafted web content may lead to
 arbitrary code execution. Multiple memory corruption issues were
 addressed with improved memory handling.

CVE-2019-6217: Processing maliciously crafted web content may lead to
 arbitrary code execution. Multiple memory corruption issues were
 addressed with improved memory handling.

CVE-2019-6226: Processing maliciously crafted web content may lead to
 arbitrary code execution. Multiple memory corruption issues were
 addressed with improved memory handling.

CVE-2019-6227: Processing maliciously crafted web content may lead to
 arbitrary code execution. A memory corruption issue was addressed with
 improved memory handling.

CVE-2019-6229: Processing maliciously crafted web content may lead to
 universal cross site scripting. A logic issue was addressed with
 improved validation.

CVE-2019-6233: Processing maliciously crafted web content may lead to
 arbitrary code execution. A memory corruption issue was addressed with
 improved memory handling.

CVE-2019-6234: Processing maliciously crafted web content may lead to
 arbitrary code execution. A memory corruption issue was addressed with
 improved memory handling.

Other bug fixes and changes:
Make kinetic scrolling slow down smoothly when ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'webkit2gtk3' package(s) on SUSE Linux Enterprise Module for Basesystem 15, SUSE Linux Enterprise Module for Desktop Applications 15, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4_0-18", rpm:"libjavascriptcoregtk-4_0-18~2.22.6~3.18.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4_0-18-debuginfo", rpm:"libjavascriptcoregtk-4_0-18-debuginfo~2.22.6~3.18.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4_0-37", rpm:"libwebkit2gtk-4_0-37~2.22.6~3.18.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4_0-37-debuginfo", rpm:"libwebkit2gtk-4_0-37-debuginfo~2.22.6~3.18.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk3-lang", rpm:"libwebkit2gtk3-lang~2.22.6~3.18.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4_0-injected-bundles", rpm:"webkit2gtk-4_0-injected-bundles~2.22.6~3.18.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4_0-injected-bundles-debuginfo", rpm:"webkit2gtk-4_0-injected-bundles-debuginfo~2.22.6~3.18.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-debugsource", rpm:"webkit2gtk3-debugsource~2.22.6~3.18.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-JavaScriptCore-4_0", rpm:"typelib-1_0-JavaScriptCore-4_0~2.22.6~3.18.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2-4_0", rpm:"typelib-1_0-WebKit2-4_0~2.22.6~3.18.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2WebExtension-4_0", rpm:"typelib-1_0-WebKit2WebExtension-4_0~2.22.6~3.18.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-devel", rpm:"webkit2gtk3-devel~2.22.6~3.18.2", rls:"SLES15.0"))) {
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
