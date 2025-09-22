# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.1874.1");
  script_cve_id("CVE-2021-33813");
  script_tag(name:"creation_date", value:"2024-06-03 04:26:52 +0000 (Mon, 03 Jun 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-21 22:21:48 +0000 (Mon, 21 Jun 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:1874-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2|SLES15\.0SP3|SLES15\.0SP4|SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1874-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20241874-1.html");
  script_xref(name:"URL", value:"http://xml.org/sax/properties/external-general-entities");
  script_xref(name:"URL", value:"http://xml.org/sax/properties/external-parameter-entities");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187446");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224410");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-May/035436.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Java' package(s) announced via the SUSE-SU-2024:1874-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for Java fixes thefollowing issues:

apiguardian was updated to vesion 1.1.2:

- Added LICENSE/NOTICE to the generated jar
- Allow @API to be declared at the package level
- Explain usage of Status.DEPRECATED
- Include OSGi metadata in manifest

assertj-core was implemented at version 3.25.3:

- New package implementation needed by Junit5

byte-buddy was updated to version v1.14.16:

- `byte-buddy` is required by `assertj-core`
- Changes in version v1.14.16:

 * Update ASM and introduce support for Java 23.

- Changes in version v1.14.15:

 * Allow attaching from root on J9.

- Changes of v1.14.14:

 * Adjust type validation to accept additional names that are
 legal in the class file format.
 * Fix dynamic attach on Windows when a service user is active.
 * Avoid failure when using Android's strict mode.

dom4j was updated to version 2.1.4:

- Improvements and potentially breaking changes:

 * Added new factory method org.dom4j.io.SAXReader.createDefault(). It has more secure defaults than new SAXReader(),
 which uses system XMLReaderFactory.createXMLReader() or SAXParserFactory.newInstance().newSAXParser().
 * If you use some optional dependency of dom4j (for example Jaxen, xsdlib etc.), you need to specify an explicit
 dependency on it in your project. They are no longer marked as a mandatory transitive dependency by dom4j.
 * Following SAX parser features are disabled by default in DocumentHelper.parse() for security reasons (they were
 enabled in previous versions):

 + [link moved to references]
 + [link moved to references]

- Other changes:

 * Do not depend on jtidy, since it is not used during build
 * Fixed license to Plexus
 * JPMS: Add the Automatic-Module-Name attribute to the manifest.
 * Make a separate flavour for a minimal `dom4j-bootstrap` package used to build `jaxen` and full `dom4j`
 * Updated pull-parser version
 * Reuse the writeAttribute method in writeAttributes
 * Support build on OS with non-UTF8 as default charset
 * Gradle: add an automatic module name
 * Use Correct License Name 'Plexus'
 * Possible vulnerability of DocumentHelper.parseText() to XML injection
 * CVS directories left in the source tree
 * XMLWriter does not escape supplementary unicode characters correctly
 * writer.writeOpen(x) doesn't write namespaces
 * Fixed concurrency problem with QNameCache
 * All dependencies are optional
 * SAXReader: hardcoded namespace features
 * Validate QNames
 * StringIndexOutOfBoundsException in XMLWriter.writeElementContent()
 * TreeNode has grown some generics
 * QName serialization fix
 * DocumentException initialize with nested exception
 * Accidentally occurring error in a multi-threaded test
 * Added compatibility with W3C DOM Level 3
 * Use Java generics

hamcrest:

- `hamcrest-core` has been replaced by `hamcrest` (no source changes)

junit had the following change:

- Require hamcrest >= 2.2

junit5 was updated to version ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Java' package(s) on SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server 15-SP6, SUSE Linux Enterprise Server for SAP Applications 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP4.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"dom4j", rpm:"dom4j~2.1.4~150200.12.10.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hamcrest", rpm:"hamcrest~2.2~150200.12.17.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jaxen", rpm:"jaxen~2.0.0~150200.5.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jdom", rpm:"jdom~1.1.3~150200.12.8.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"junit", rpm:"junit~4.13.2~150200.3.15.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"objectweb-asm", rpm:"objectweb-asm~9.7~150200.3.15.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xom", rpm:"xom~1.3.9~150200.5.3.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"dom4j", rpm:"dom4j~2.1.4~150200.12.10.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hamcrest", rpm:"hamcrest~2.2~150200.12.17.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jaxen", rpm:"jaxen~2.0.0~150200.5.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jdom", rpm:"jdom~1.1.3~150200.12.8.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"junit", rpm:"junit~4.13.2~150200.3.15.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"objectweb-asm", rpm:"objectweb-asm~9.7~150200.3.15.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xom", rpm:"xom~1.3.9~150200.5.3.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"dom4j", rpm:"dom4j~2.1.4~150200.12.10.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hamcrest", rpm:"hamcrest~2.2~150200.12.17.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jaxen", rpm:"jaxen~2.0.0~150200.5.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jdom", rpm:"jdom~1.1.3~150200.12.8.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"junit", rpm:"junit~4.13.2~150200.3.15.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"objectweb-asm", rpm:"objectweb-asm~9.7~150200.3.15.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xom", rpm:"xom~1.3.9~150200.5.3.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"objectweb-asm", rpm:"objectweb-asm~9.7~150200.3.15.2", rls:"SLES15.0SP6"))) {
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
