# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.02056.1");
  script_cve_id("CVE-2014-0114", "CVE-2015-4852", "CVE-2025-48734");
  script_tag(name:"creation_date", value:"2025-06-23 04:17:35 +0000 (Mon, 23 Jun 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2015-11-19 13:38:59 +0000 (Thu, 19 Nov 2015)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:02056-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02056-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502056-1.html");
  script_xref(name:"URL", value:"http://commons.apache.org/proper/commons-beanutils/changes-report.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243793");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-June/040424.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache-commons-beanutils' package(s) announced via the SUSE-SU-2025:02056-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for apache-commons-beanutils fixes the following issues:

Update to 1.11.0:

 * Fixed Bugs:

 + BeanComparator.compare(T, T) now throws
 IllegalArgumentException instead of RuntimeException to wrap
 all cases of ReflectiveOperationException.
 + MappedMethodReference.get() now throws IllegalStateException
 instead of RuntimeException to wrap cases of
 NoSuchMethodException.
 + ResultSetIterator.get(String) now throws
 IllegalArgumentException instead of RuntimeException to wrap
 cases of SQLException.
 + ResultSetIterator.hasNext() now throws IllegalStateException
 instead of RuntimeException to wrap cases of SQLException.
 + ResultSetIterator.next() now throws IllegalStateException
 instead of RuntimeException to wrap cases of SQLException.
 + ResultSetIterator.set(String, Object) now throws
 IllegalArgumentException instead of RuntimeException to wrap
 cases of SQLException.
 + ResultSetIterator.set(String, String, Object) now throws
 IllegalArgumentException instead of RuntimeException to wrap
 cases of SQLException.

 * Changes:

 + Add org.apache.commons.beanutils
 .SuppressPropertiesBeanIntrospector.SUPPRESS_DECLARING_CLASS.
 Fixes bsc#1243793, CVE-2025-48734
 + Bump org.apache.commons:commons-parent from 81 to 84.
 + Bump commons-logging:commons-logging from 1.3.4 to 1.3.5.

Update to 1.10.1:

 * Fixed Bugs:

 + BEANUTILS-541: FluentPropertyBeanIntrospector concurrency
 issue (backport to 1.X) #325.
 + Javadoc is missing its Overview page.
 + Remove -nouses directive from maven-bundle-plugin. OSGi
 package imports now state 'uses' definitions for package
 imports, this doesn't affect JPMS (from
 org.apache.commons:commons-parent:80).
 + Deprecate BeanUtils.BeanUtils().
 + Deprecate ConstructorUtils.ConstructorUtils().
 + Deprecate LocaleBeanUtils.LocaleBeanUtils().
 + Deprecate LocaleConvertUtils.LocaleConvertUtils().
 + Deprecate ConvertUtils.ConvertUtils().
 + Deprecate MethodUtils.MethodUtils().
 + Deprecate PropertyUtils.PropertyUtils().

 * Changes:

 + Bump org.apache.commons:commons-parent from 78 to 81.

Includes changes from 1.10.0:

 * Fixed Bugs:

 + BEANUTILS-541: FluentPropertyBeanIntrospector caches
 corrupted writeMethod (1.x backport) #69.
 + Replace internal use of Locale.ENGLISH with Locale.ROOT.
 + Replace Maven CLIRR plugin with JApiCmp.
 + Port to Java 1.4 Throwable APIs (!).
 + Fix Javadoc generation on Java 8, 17, and 21.
 + AbstractArrayConverter.parseElements(String) now returns a
 List<String> instead of a raw List.

 * Changes:

 + Bump org.apache.commons:commons-parent from 47 to 78.
 + Bump Java requirement from Java 6 to 8.
 + Bump junit:junit from 4.12 to 4.13.2.
 + Bump JUnit from 4.x to 5.x 'vintage'.
 + Bump commons-logging:commons-logging from 1.2 to 1.3.4.
 + Deprecate BeanUtilsBean.initCause(Throwable, Throwable) for
 removal, use Throwable.initCause(Throwable).
 + Deprecate BeanUtils.initCause(Throwable, Throwable) ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'apache-commons-beanutils' package(s) on SUSE Linux Enterprise Server 12-SP5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"apache-commons-beanutils", rpm:"apache-commons-beanutils~1.11.0~7.3.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-commons-beanutils-javadoc", rpm:"apache-commons-beanutils-javadoc~1.11.0~7.3.1", rls:"SLES12.0SP5"))) {
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
