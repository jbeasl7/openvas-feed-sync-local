# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.0577.1");
  script_cve_id("CVE-2023-47627", "CVE-2023-47641", "CVE-2023-49081", "CVE-2023-49082", "CVE-2024-23334", "CVE-2024-23829");
  script_tag(name:"creation_date", value:"2024-02-22 04:21:09 +0000 (Thu, 22 Feb 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-05 18:44:40 +0000 (Mon, 05 Feb 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:0577-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0577-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240577-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217174");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217181");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217782");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219341");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219342");
  script_xref(name:"URL", value:"https://github.com/aio-libs/aiohttp/security/advisories/GHSA-");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-February/017982.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-aiohttp, python-time-machine' package(s) announced via the SUSE-SU-2024:0577-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-aiohttp, python-time-machine fixes the following issues:

python-aiohttp was updated to version 3.9.3:

* Fixed backwards compatibility breakage (in 3.9.2) of ``ssl`` parameter
 when set outside of ``ClientSession`` (e.g. directly in ``TCPConnector``)
* Improved test suite handling of paths and temp files to consistently
 use pathlib and pytest fixtures.

From version 3.9.2 (bsc#1219341, CVE-2024-23334, bsc#1219342, CVE-2024-23829):

* Fixed server-side websocket connection leak.
* Fixed ``web.FileResponse`` doing blocking I/O in the event loop.
* Fixed double compress when compression enabled and compressed file
 exists in server file responses.
* Added runtime type check for ``ClientSession`` ``timeout`` parameter.
* Fixed an unhandled exception in the Python HTTP parser on header lines
 starting with a colon.
* Improved validation of paths for static resources requests to the server.
* Added support for passing :py:data:`True` to ``ssl`` parameter in
 ``ClientSession`` while deprecating :py:data:`None`.
* Fixed an unhandled exception in the Python HTTP parser on header lines
 starting with a colon.
* Fixed examples of ``fallback_charset_resolver`` function in the
 :doc:`client_advanced` document.
* The Sphinx setup was updated to avoid showing the empty
 changelog draft section in the tagged release documentation
 builds on Read The Docs.
* The changelog categorization was made clearer. The contributors can
 now mark their fragment files more accurately.
* Updated :ref:`contributing/Tests coverage <aiohttp-contributing>`
 section to show how we use ``codecov``.
* Replaced all ``tmpdir`` fixtures with ``tmp_path`` in test suite.

- Disable broken tests with openssl 3.2 and python < 3.11 bsc#1217782

update to 3.9.1:

* Fixed importing aiohttp under PyPy on Windows.
* Fixed async concurrency safety in websocket compressor.
* Fixed ``ClientResponse.close()`` releasing the connection
 instead of closing.
* Fixed a regression where connection may get closed during
 upgrade. -- by :user:`Dreamsorcerer`
* Fixed messages being reported as upgraded without an Upgrade
 header in Python parser. -- by :user:`Dreamsorcerer`

update to 3.9.0: (bsc#1217684, CVE-2023-49081, bsc#1217682, CVE-2023-49082)

* Introduced ``AppKey`` for static typing support of
 ``Application`` storage.
* Added a graceful shutdown period which allows pending tasks
 to complete before the application's cleanup is called.
* Added `handler_cancellation`_ parameter to cancel web handler on
 client disconnection.
* This (optionally) reintroduces a feature removed in a
 previous release.
* Recommended for those looking for an extra level of
 protection against denial-of-service attacks.
* Added support for setting response header parameters
 ``max_line_size`` and ``max_field_size``.
* Added ``auto_decompress`` parameter to
 ``ClientSession.request`` to override
 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'python-aiohttp, python-time-machine' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP4.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"python311-aiohttp", rpm:"python311-aiohttp~3.9.3~150400.10.14.1", rls:"SLES15.0SP4"))) {
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
