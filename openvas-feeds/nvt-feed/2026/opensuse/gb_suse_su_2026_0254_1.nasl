# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2026.0254.1");
  script_cve_id("CVE-2025-68161");
  script_tag(name:"creation_date", value:"2026-01-26 08:38:31 +0000 (Mon, 26 Jan 2026)");
  script_version("2026-01-27T05:49:07+0000");
  script_tag(name:"last_modification", value:"2026-01-27 05:49:07 +0000 (Tue, 27 Jan 2026)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-12 15:26:10 +0000 (Mon, 12 Jan 2026)");

  script_name("openSUSE Security Advisory (SUSE-SU-2026:0254-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0254-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260254-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255427");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-January/023894.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'log4j' package(s) announced via the SUSE-SU-2026:0254-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- CVE-2025-68161: Fixed absent TLS hostname verification
 that may allow a man-in-the-middle attack (bsc#1255427)

Other fixes:

- Upgrade to 2.18.0
 * Added
 + Add support for Jakarta Mail API in the SMTP appender.
 + Add support for custom Log4j 1.x levels.
 + Add support for adding and retrieving appenders in Log4j 1.x
 bridge.
 + Add support for custom LMAX disruptor WaitStrategy
 configuration.
 + Add support for Apache Extras' RollingFileAppender in Log4j
 1.x bridge.
 + Add MutableThreadContextMapFilter.
 + Add support for 24 colors in highlighting
 * Changed
 + Improves ServiceLoader support on servlet containers.
 + Make the default disruptor WaitStrategy used by Async Loggers
 garbage-free.
 + Do not throw UnsupportedOperationException when JUL
 ApiLogger::setLevel is called.
 + Support Spring 2.6.x.
 + Move perf tests to log4j-core-its
 + Upgrade the Flume Appender to Flume 1.10.0
 * Fixed
 + Fix minor typo #792.
 + Improve validation and reporting of configuration errors.
 + Allow enterprise id to be an OID fragment.
 + Fix problem with non-uppercase custom levels.
 + Avoid ClassCastException in JeroMqManager with custom
 LoggerContextFactory #791.
 + DirectWriteRolloverStrategy should use the current time when
 creating files.
 + Fixes the syslog appender in Log4j 1.x bridge, when used with
 a custom layout.
 + log4j-1.2-api 2.17.2 throws NullPointerException while
 removing appender with name as null.
 + Improve JsonTemplateLayout performance.
 + Fix resolution of non-Log4j properties.
 + Fixes Spring Boot logging system registration in a
 multi-application environment.
 + JAR file containing Log4j configuration isn't closed.
 + Properties defined in configuration using a value attribute
 (as opposed to element) are read correctly.
 + Syslog appender lacks the SocketOptions setting.
 + Log4j 1.2 bridge should not wrap components unnecessarily.
 + Update 3rd party dependencies for 2.18.0.
 + SizeBasedTriggeringPolicy would fail to rename files properly
 when integer pattern contained a leading zero.
 + Fixes default SslConfiguration, when a custom keystore is
 used.
 + Fixes appender concurrency problems in Log4j 1.x bridge.
 + Fix and test for race condition in FileUtils.mkdir().
 + LocalizedMessage logs misleading errors on the console.
 + Add missing message parameterization in RegexFilter.
 + Add the missing context stack to JsonLayout template.
 + HttpWatcher did not pass credentials when polling.
 + UrlConnectionFactory.createConnection now accepts an
 AuthorizationProvider as a parameter.
 + The DirectWriteRolloverStrategy was not detecting the correct
 index to use during startup.
 + Async Loggers were including the location information by
 default.
 + ClassArbiter's newBuilder method referenced the wrong class.
 + Don't use Paths.get() to avoid circular file systems.
 + Fix parsing error, when XInclude is disabled.
 + Fix LevelRangeFilterBuilder to ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'log4j' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"log4j", rpm:"log4j~2.20.0~150200.4.30.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"log4j-javadoc", rpm:"log4j-javadoc~2.20.0~150200.4.30.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"log4j-jcl", rpm:"log4j-jcl~2.20.0~150200.4.30.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"log4j-slf4j", rpm:"log4j-slf4j~2.20.0~150200.4.30.1", rls:"openSUSELeap15.6"))) {
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
