# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.2082");
  script_cve_id("CVE-2018-16858", "CVE-2019-9848", "CVE-2019-9850", "CVE-2019-9851", "CVE-2019-9852");
  script_tag(name:"creation_date", value:"2020-01-23 12:33:43 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-28 21:10:17 +0000 (Wed, 28 Aug 2019)");

  script_name("Huawei EulerOS: Security Advisory for libreoffice (EulerOS-SA-2019-2082)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP8");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-2082");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-2082");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'libreoffice' package(s) announced via the EulerOS-SA-2019-2082 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"libreoffice: Arbitrary python functions in arbitrary modules on the filesystem can be executed without warning (CVE-2018-16858)

LibreOffice has a feature where documents can specify that pre-installed scripts can be executed on various document events such as mouse-over, etc. LibreOffice is typically also bundled with LibreLogo, a programmable turtle vector graphics script, which can be manipulated into executing arbitrary python commands. By using the document event feature to trigger LibreLogo to execute python contained within a document a malicious document could be constructed which would execute arbitrary python commands silently without warning. In the fixed versions, LibreLogo cannot be called from a document event handler. This issue affects: Document Foundation LibreOffice versions prior to 6.2.5.(CVE-2019-9848)

LibreOffice is typically bundled with LibreLogo, a programmable turtle vector graphics script, which can execute arbitrary python commands contained with the document it is launched from. LibreOffice also has a feature where documents can specify that pre-installed scripts can be executed on various document script events such as mouse-over, etc. Protection was added, to address CVE-2019-9848, to block calling LibreLogo from script event handers. However an insufficient url validation vulnerability in LibreOffice allowed malicious to bypass that protection and again trigger calling LibreLogo from script event handlers. This issue affects: Document Foundation LibreOffice versions prior to 6.2.6.(CVE-2019-9850)

LibreOffice is typically bundled with LibreLogo, a programmable turtle vector graphics script, which can execute arbitrary python commands contained with the document it is launched from. Protection was added, to address CVE-2019-9848, to block calling LibreLogo from document event script handers, e.g. mouse over. However LibreOffice also has a separate feature where documents can specify that pre-installed scripts can be executed on various global script events such as document-open, etc. In the fixed versions, global script event handlers are validated equivalently to document script event handlers. This issue affects: Document Foundation LibreOffice versions prior to 6.2.6.(CVE-2019-9851)

LibreOffice has a feature where documents can specify that pre-installed macros can be executed on various script events such as mouse-over, document-open etc. Access is intended to be restricted to scripts under the share/Scripts/python, user/Scripts/python sub-directories of the LibreOffice install. Protection was added, to address CVE-2018-16858, to avoid a directory traversal attack where scripts in arbitrary locations on the file system could be executed. However this new protection could be bypassed by a URL encoding attack. In the fixed versions, the parsed url describing the script location is correctly encoded before further processing. This issue ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'libreoffice' package(s) on Huawei EulerOS V2.0SP8.");

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

if(release == "EULEROS-2.0SP8") {

  if(!isnull(res = isrpmvuln(pkg:"autocorr-en", rpm:"autocorr-en~6.1.1.2~1.h2.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-core", rpm:"libreoffice-core~6.1.1.2~1.h2.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-data", rpm:"libreoffice-data~6.1.1.2~1.h2.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-gtk2", rpm:"libreoffice-gtk2~6.1.1.2~1.h2.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-gtk3", rpm:"libreoffice-gtk3~6.1.1.2~1.h2.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-en", rpm:"libreoffice-langpack-en~6.1.1.2~1.h2.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-opensymbol-fonts", rpm:"libreoffice-opensymbol-fonts~6.1.1.2~1.h2.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-ure", rpm:"libreoffice-ure~6.1.1.2~1.h2.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-ure-common", rpm:"libreoffice-ure-common~6.1.1.2~1.h2.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-x11", rpm:"libreoffice-x11~6.1.1.2~1.h2.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreofficekit", rpm:"libreofficekit~6.1.1.2~1.h2.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
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
