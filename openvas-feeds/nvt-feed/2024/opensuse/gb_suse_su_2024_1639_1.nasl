# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856161");
  script_cve_id("CVE-2023-28858", "CVE-2023-28859");
  script_tag(name:"creation_date", value:"2024-05-24 01:10:40 +0000 (Fri, 24 May 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-05 19:06:46 +0000 (Wed, 05 Apr 2023)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:1639-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5|openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1639-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20241639-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209571");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209811");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209812");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216606");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222880");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/761162");
  script_xref(name:"URL", value:"https://github.com/gabrielfalcao/sure/pull/161");
  script_xref(name:"URL", value:"https://github.com/kevin1024/vcrpy/releases");
  script_xref(name:"URL", value:"https://github.com/python-semver/python-semver/discussions/371");
  script_xref(name:"URL", value:"https://github.com/python-semver/python-semver/tree/master/changelog.d");
  script_xref(name:"URL", value:"https://godatadriven.com/blog/a-practical-guide-to-setuptools-and-pyproject-toml/");
  script_xref(name:"URL", value:"https://hitchdev.com/strictyaml/changelog/");
  script_xref(name:"URL", value:"https://hitchdev.com/strictyaml/changelog/#latest");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-May/035268.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-Fabric, python-PyGithub, python-antlr4-python3-runtime, python-arcomplete, python-avro, python-chardet, python-distro, python-docker, python-fakeredis, python-fixedint, python-httplib2, python-httpretty, python-javaproperties, python-jsondiff, python-knack, python-marshmallow, python-opencensus, python-opencensus-context, python-opencensus-ext-threading, python-opentelemetry-api, python-opentelemetry-sdk, python-opentelemetry-semantic-conventions, python-opentelemetry-test-utils, python-pycomposefile, python-pydash, python-redis, python-retrying, python-semver, python-sshtunnel, python-strictyaml, python-sure, python-vcrpy, python-xmltodict' package(s) announced via the SUSE-SU-2024:1639-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- :gh:`374`: Correct Towncrier's config entries in the :file:`pyproject.toml` file.
 The old entries ``[[tool.towncrier.type]]`` are deprecated and need
 to be replaced by ``[tool.towncrier.fragment.<TYPE>]``.
 - Deprecations:
 - :gh:`372`: Deprecate support for Python 3.6.
 Python 3.6 reached its end of life and isn't supported anymore.
 At the time of writing (Dec 2022), the lowest version is 3.7.
 Although the `poll <[link moved to references]
 didn't cast many votes, the majority agree to remove support for
 Python 3.6.
 - Improved Documentation:
 - :gh:`335`: Add new section 'Converting versions between PyPI and semver' the limitations
 and possible use cases to convert from one into the other versioning scheme.
 - :gh:`340`: Describe how to get version from a file
 - :gh:`343`: Describe combining Pydantic with semver in the 'Advanced topic'
 section.
 - :gh:`350`: Restructure usage section. Create subdirectory 'usage/' and splitted
 all section into different files.
 - :gh:`351`: Introduce new topics for:
 * 'Migration to semver3'
 * 'Advanced topics'
 - Features:
 - :pr:`359`: Add optional parameter ``optional_minor_and_patch`` in :meth:`.Version.parse` to allow optional
 minor and patch parts.
 - :pr:`362`: Make :meth:`.Version.match` accept a bare version string as match expression, defaulting to
 equality testing.
 - :gh:`364`: Enhance :file:`pyproject.toml` to make it possible to use the
 :command:`pyproject-build` command from the build module.
 For more information, see :ref:`build-semver`.
 - :gh:`365`: Improve :file:`pyproject.toml`.
 * Use setuptools, add metadata. Taken approach from
 `A Practical Guide to Setuptools and Pyproject.toml
 <[link moved to references].
 * Doc: Describe building of semver
 * Remove :file:`.travis.yml` in :file:`MANIFEST.in`
 (not needed anymore)
 * Distinguish between Python 3.6 and others in :file:`tox.ini`
 * Add skip_missing_interpreters option for :file:`tox.ini`
 * GH Action: Upgrade setuptools and setuptools-scm and test
 against 3.11.0-rc.2
 - Trivial/Internal Changes:
 - :gh:`378`: Fix some typos in Towncrier configuration

- switch to the tagged version rather than a gh branch tarball

- fix support for Python 3.10 with update to development version:
- update to revision g4d2df08:
 - Changes for the upcoming release can be found in:
 - the `'changelog.d' directory <[link moved to references]:
 - in our repository.:
- update to version 3.0.0-dev.2:
 - Deprecations:
 - :gh:`169`: Deprecate CLI functions not imported from ``semver.cli``.
 - Features:
 - :gh:`169`: Create semver package and split code among different modules in the packages.
 * Remove :file:`semver.py`
 * Create :file:`src/semver/__init__.py`
 * Create :file:`src/semver/cli.py` for all CLI methods
 * Create :file:`src/semver/_deprecated.py` for the ``deprecated`` decorator and other deprecated functions
 * Create :file:`src/semver/__main__.py` to allow ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'python-Fabric, python-PyGithub, python-antlr4-python3-runtime, python-arcomplete, python-avro, python-chardet, python-distro, python-docker, python-fakeredis, python-fixedint, python-httplib2, python-httpretty, python-javaproperties, python-jsondiff, python-knack, python-marshmallow, python-opencensus, python-opencensus-context, python-opencensus-ext-threading, python-opentelemetry-api, python-opentelemetry-sdk, python-opentelemetry-semantic-conventions, python-opentelemetry-test-utils, python-pycomposefile, python-pydash, python-redis, python-retrying, python-semver, python-sshtunnel, python-strictyaml, python-sure, python-vcrpy, python-xmltodict' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"python-paramiko-doc", rpm:"python-paramiko-doc~3.4.0~150400.13.10.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-tqdm-bash-completion", rpm:"python-tqdm-bash-completion~4.66.1~150400.9.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Automat", rpm:"python311-Automat~22.10.0~150400.3.7.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Deprecated", rpm:"python311-Deprecated~1.2.14~150400.10.7.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Fabric", rpm:"python311-Fabric~3.2.2~150400.10.4.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-PyGithub", rpm:"python311-PyGithub~1.57~150400.10.4.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-PyJWT", rpm:"python311-PyJWT~2.8.0~150400.8.7.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Pygments", rpm:"python311-Pygments~2.15.1~150400.7.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted", rpm:"python311-Twisted~22.10.0~150400.5.17.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted-all_non_platform", rpm:"python311-Twisted-all_non_platform~22.10.0~150400.5.17.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted-conch", rpm:"python311-Twisted-conch~22.10.0~150400.5.17.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted-conch_nacl", rpm:"python311-Twisted-conch_nacl~22.10.0~150400.5.17.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted-contextvars", rpm:"python311-Twisted-contextvars~22.10.0~150400.5.17.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted-http2", rpm:"python311-Twisted-http2~22.10.0~150400.5.17.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted-serial", rpm:"python311-Twisted-serial~22.10.0~150400.5.17.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted-tls", rpm:"python311-Twisted-tls~22.10.0~150400.5.17.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-aiohttp", rpm:"python311-aiohttp~3.9.3~150400.10.18.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-aiosignal", rpm:"python311-aiosignal~1.3.1~150400.9.7.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-antlr4-python3-runtime", rpm:"python311-antlr4-python3-runtime~4.13.1~150400.10.4.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-argcomplete", rpm:"python311-argcomplete~3.3.0~150400.12.12.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-asgiref", rpm:"python311-asgiref~3.6.0~150400.9.7.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-async_timeout", rpm:"python311-async_timeout~4.0.2~150400.10.7.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-avro", rpm:"python311-avro~1.11.3~150400.10.4.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-blinker", rpm:"python311-blinker~1.6.2~150400.12.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-chardet", rpm:"python311-chardet~5.2.0~150400.13.7.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-constantly", rpm:"python311-constantly~15.1.0~150400.12.7.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-decorator", rpm:"python311-decorator~5.1.1~150400.12.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-distro", rpm:"python311-distro~1.9.0~150400.12.4.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-docker", rpm:"python311-docker~7.0.0~150400.8.4.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-fakeredis", rpm:"python311-fakeredis~2.21.0~150400.9.3.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-fixedint", rpm:"python311-fixedint~0.2.0~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-fluidity-sm", rpm:"python311-fluidity-sm~0.2.0~150400.10.7.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-frozenlist", rpm:"python311-frozenlist~1.3.3~150400.9.7.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-httplib2", rpm:"python311-httplib2~0.22.0~150400.10.4.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-httpretty", rpm:"python311-httpretty~1.1.4~150400.11.4.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-humanfriendly", rpm:"python311-humanfriendly~10.0~150400.13.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-hyperlink", rpm:"python311-hyperlink~21.0.0~150400.12.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-importlib-metadata", rpm:"python311-importlib-metadata~6.8.0~150400.10.9.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-incremental", rpm:"python311-incremental~22.10.0~150400.3.7.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-invoke", rpm:"python311-invoke~2.1.2~150400.10.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-isodate", rpm:"python311-isodate~0.6.1~150400.12.7.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-javaproperties", rpm:"python311-javaproperties~0.8.1~150400.10.4.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-jsondiff", rpm:"python311-jsondiff~2.0.0~150400.10.4.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-knack", rpm:"python311-knack~0.11.0~150400.10.4.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-lexicon", rpm:"python311-lexicon~2.0.1~150400.10.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-marshmallow", rpm:"python311-marshmallow~3.20.2~150400.9.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-multidict", rpm:"python311-multidict~6.0.4~150400.7.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-oauthlib", rpm:"python311-oauthlib~3.2.2~150400.12.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-opencensus", rpm:"python311-opencensus~0.11.4~150400.10.6.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-opencensus-context", rpm:"python311-opencensus-context~0.1.3~150400.10.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-opencensus-ext-threading", rpm:"python311-opencensus-ext-threading~0.1.2~150400.10.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-opentelemetry-api", rpm:"python311-opentelemetry-api~1.23.0~150400.10.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-opentelemetry-sdk", rpm:"python311-opentelemetry-sdk~1.23.0~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-opentelemetry-semantic-conventions", rpm:"python311-opentelemetry-semantic-conventions~0.44b0~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-opentelemetry-test-utils", rpm:"python311-opentelemetry-test-utils~0.44b0~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-paramiko", rpm:"python311-paramiko~3.4.0~150400.13.10.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-pathspec", rpm:"python311-pathspec~0.11.1~150400.9.7.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-pip", rpm:"python311-pip~22.3.1~150400.17.16.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-pkginfo", rpm:"python311-pkginfo~1.9.6~150400.7.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-portalocker", rpm:"python311-portalocker~2.7.0~150400.10.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-psutil", rpm:"python311-psutil~5.9.5~150400.6.9.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-pycomposefile", rpm:"python311-pycomposefile~0.0.30~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-pydash", rpm:"python311-pydash~6.0.2~150400.9.4.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-pyparsing", rpm:"python311-pyparsing~3.0.9~150400.5.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-redis", rpm:"python311-redis~5.0.1~150400.12.4.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-requests-oauthlib", rpm:"python311-requests-oauthlib~1.3.1~150400.12.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-retrying", rpm:"python311-retrying~1.3.4~150400.12.4.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-scp", rpm:"python311-scp~0.14.5~150400.12.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-semver", rpm:"python311-semver~3.0.2~150400.10.4.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-service_identity", rpm:"python311-service_identity~23.1.0~150400.8.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-sortedcontainers", rpm:"python311-sortedcontainers~2.4.0~150400.8.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-sshtunnel", rpm:"python311-sshtunnel~0.4.0~150400.5.4.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-strictyaml", rpm:"python311-strictyaml~1.7.3~150400.9.3.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-sure", rpm:"python311-sure~2.0.1~150400.12.4.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-tabulate", rpm:"python311-tabulate~0.9.0~150400.11.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-tqdm", rpm:"python311-tqdm~4.66.1~150400.9.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-typing_extensions", rpm:"python311-typing_extensions~4.5.0~150400.3.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-vcrpy", rpm:"python311-vcrpy~6.0.1~150400.7.4.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-websocket-client", rpm:"python311-websocket-client~1.5.1~150400.13.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-wheel", rpm:"python311-wheel~0.40.0~150400.13.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-wrapt", rpm:"python311-wrapt~1.15.0~150400.12.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-xmltodict", rpm:"python311-xmltodict~0.13.0~150400.12.4.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-yarl", rpm:"python311-yarl~1.9.2~150400.8.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-zipp", rpm:"python311-zipp~3.15.0~150400.10.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-zope.interface", rpm:"python311-zope.interface~6.0~150400.12.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"python-paramiko-doc", rpm:"python-paramiko-doc~3.4.0~150400.13.10.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-tqdm-bash-completion", rpm:"python-tqdm-bash-completion~4.66.1~150400.9.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Automat", rpm:"python311-Automat~22.10.0~150400.3.7.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Deprecated", rpm:"python311-Deprecated~1.2.14~150400.10.7.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Fabric", rpm:"python311-Fabric~3.2.2~150400.10.4.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-PyGithub", rpm:"python311-PyGithub~1.57~150400.10.4.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-PyJWT", rpm:"python311-PyJWT~2.8.0~150400.8.7.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Pygments", rpm:"python311-Pygments~2.15.1~150400.7.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted", rpm:"python311-Twisted~22.10.0~150400.5.17.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted-all_non_platform", rpm:"python311-Twisted-all_non_platform~22.10.0~150400.5.17.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted-conch", rpm:"python311-Twisted-conch~22.10.0~150400.5.17.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted-conch_nacl", rpm:"python311-Twisted-conch_nacl~22.10.0~150400.5.17.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted-contextvars", rpm:"python311-Twisted-contextvars~22.10.0~150400.5.17.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted-http2", rpm:"python311-Twisted-http2~22.10.0~150400.5.17.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted-serial", rpm:"python311-Twisted-serial~22.10.0~150400.5.17.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted-tls", rpm:"python311-Twisted-tls~22.10.0~150400.5.17.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-aiohttp", rpm:"python311-aiohttp~3.9.3~150400.10.18.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-aiosignal", rpm:"python311-aiosignal~1.3.1~150400.9.7.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-antlr4-python3-runtime", rpm:"python311-antlr4-python3-runtime~4.13.1~150400.10.4.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-argcomplete", rpm:"python311-argcomplete~3.3.0~150400.12.12.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-asgiref", rpm:"python311-asgiref~3.6.0~150400.9.7.3", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-async_timeout", rpm:"python311-async_timeout~4.0.2~150400.10.7.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-avro", rpm:"python311-avro~1.11.3~150400.10.4.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-blinker", rpm:"python311-blinker~1.6.2~150400.12.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-chardet", rpm:"python311-chardet~5.2.0~150400.13.7.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-constantly", rpm:"python311-constantly~15.1.0~150400.12.7.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-decorator", rpm:"python311-decorator~5.1.1~150400.12.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-distro", rpm:"python311-distro~1.9.0~150400.12.4.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-docker", rpm:"python311-docker~7.0.0~150400.8.4.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-fakeredis", rpm:"python311-fakeredis~2.21.0~150400.9.3.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-fixedint", rpm:"python311-fixedint~0.2.0~150400.9.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-fluidity-sm", rpm:"python311-fluidity-sm~0.2.0~150400.10.7.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-frozenlist", rpm:"python311-frozenlist~1.3.3~150400.9.7.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-httplib2", rpm:"python311-httplib2~0.22.0~150400.10.4.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-httpretty", rpm:"python311-httpretty~1.1.4~150400.11.4.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-humanfriendly", rpm:"python311-humanfriendly~10.0~150400.13.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-hyperlink", rpm:"python311-hyperlink~21.0.0~150400.12.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-importlib-metadata", rpm:"python311-importlib-metadata~6.8.0~150400.10.9.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-incremental", rpm:"python311-incremental~22.10.0~150400.3.7.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-invoke", rpm:"python311-invoke~2.1.2~150400.10.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-isodate", rpm:"python311-isodate~0.6.1~150400.12.7.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-javaproperties", rpm:"python311-javaproperties~0.8.1~150400.10.4.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-jsondiff", rpm:"python311-jsondiff~2.0.0~150400.10.4.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-knack", rpm:"python311-knack~0.11.0~150400.10.4.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-lexicon", rpm:"python311-lexicon~2.0.1~150400.10.7.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-marshmallow", rpm:"python311-marshmallow~3.20.2~150400.9.7.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-multidict", rpm:"python311-multidict~6.0.4~150400.7.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-oauthlib", rpm:"python311-oauthlib~3.2.2~150400.12.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-opencensus", rpm:"python311-opencensus~0.11.4~150400.10.6.3", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-opencensus-context", rpm:"python311-opencensus-context~0.1.3~150400.10.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-opencensus-ext-threading", rpm:"python311-opencensus-ext-threading~0.1.2~150400.10.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-opentelemetry-api", rpm:"python311-opentelemetry-api~1.23.0~150400.10.7.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-opentelemetry-sdk", rpm:"python311-opentelemetry-sdk~1.23.0~150400.9.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-opentelemetry-semantic-conventions", rpm:"python311-opentelemetry-semantic-conventions~0.44b0~150400.9.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-opentelemetry-test-utils", rpm:"python311-opentelemetry-test-utils~0.44b0~150400.9.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-paramiko", rpm:"python311-paramiko~3.4.0~150400.13.10.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-pathspec", rpm:"python311-pathspec~0.11.1~150400.9.7.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-pip", rpm:"python311-pip~22.3.1~150400.17.16.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-pkginfo", rpm:"python311-pkginfo~1.9.6~150400.7.7.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-portalocker", rpm:"python311-portalocker~2.7.0~150400.10.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-psutil", rpm:"python311-psutil~5.9.5~150400.6.9.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-pycomposefile", rpm:"python311-pycomposefile~0.0.30~150400.9.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-pydash", rpm:"python311-pydash~6.0.2~150400.9.4.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-pyparsing", rpm:"python311-pyparsing~3.0.9~150400.5.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-redis", rpm:"python311-redis~5.0.1~150400.12.4.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-requests-oauthlib", rpm:"python311-requests-oauthlib~1.3.1~150400.12.7.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-retrying", rpm:"python311-retrying~1.3.4~150400.12.4.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-scp", rpm:"python311-scp~0.14.5~150400.12.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-semver", rpm:"python311-semver~3.0.2~150400.10.4.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-service_identity", rpm:"python311-service_identity~23.1.0~150400.8.7.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-sortedcontainers", rpm:"python311-sortedcontainers~2.4.0~150400.8.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-sshtunnel", rpm:"python311-sshtunnel~0.4.0~150400.5.4.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-strictyaml", rpm:"python311-strictyaml~1.7.3~150400.9.3.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-tabulate", rpm:"python311-tabulate~0.9.0~150400.11.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-tqdm", rpm:"python311-tqdm~4.66.1~150400.9.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-typing_extensions", rpm:"python311-typing_extensions~4.5.0~150400.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-vcrpy", rpm:"python311-vcrpy~6.0.1~150400.7.4.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-websocket-client", rpm:"python311-websocket-client~1.5.1~150400.13.7.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-wheel", rpm:"python311-wheel~0.40.0~150400.13.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-wrapt", rpm:"python311-wrapt~1.15.0~150400.12.7.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-yarl", rpm:"python311-yarl~1.9.2~150400.8.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-zipp", rpm:"python311-zipp~3.15.0~150400.10.7.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-zope.interface", rpm:"python311-zope.interface~6.0~150400.12.7.4", rls:"openSUSELeap15.6"))) {
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
