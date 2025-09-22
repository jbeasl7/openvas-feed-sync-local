# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.0792.1");
  script_cve_id("CVE-2018-10903");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-10 16:32:13 +0000 (Wed, 10 Oct 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:0792-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3|SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:0792-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20200792-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055478");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1070737");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101820");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111657");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138748");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149792");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/981848");
  script_xref(name:"URL", value:"https://cffi.readthedocs.org/");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-March/006644.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-cffi, python-cryptography' package(s) announced via the SUSE-SU-2020:0792-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-cffi, python-cryptography fixes the following issues:

Security issue fixed:

- CVE-2018-10903: Fixed GCM tag forgery via truncated tag in finalize_with_tag API (bsc#1101820).

Non-security issues fixed:

python-cffi was updated to 1.11.2 (bsc#1138748, jsc#ECO-1256, jsc#PM-1598):

- fixed a build failure on i586 (bsc#1111657)
- Salt was unable to highstate in snapshot 20171129 (bsc#1070737)

- Update pytest in spec to add c directory tests in addition to
 testing directory.

- update to version 1.11.2:
 * Fix Windows issue with managing the thread-state on CPython 3.0 to
 3.5

- Update pytest in spec to add c directory tests in addition to
 testing directory.
- Omit test_init_once_multithread tests as they rely on multiple
 threads finishing in a given time. Returns sporadic pass/fail
 within build.
- Update to 1.11.1:
 * Fix tests, remove deprecated C API usage
 * Fix (hack) for 3.6.0/3.6.1/3.6.2 giving incompatible binary
 extensions (cpython issue #29943)
 * Fix for 3.7.0a1+

- Update to 1.11.0:
 * Support the modern standard types char16_t and char32_t. These
 work like wchar_t: they represent one unicode character, or when
 used as charN_t * or charN_t[] they represent a unicode string.
 The difference with wchar_t is that they have a known, fixed
 size. They should work at all places that used to work with
 wchar_t (please report an issue if I missed something). Note
 that with set_source(), you need to make sure that these types
 are actually defined by the C source you provide (if used in
 cdef()).
 * Support the C99 types float _Complex and double _Complex. Note
 that libffi doesn't support them, which means that in the ABI
 mode you still cannot call C functions that take complex
 numbers directly as arguments or return type.
 * Fixed a rare race condition when creating multiple FFI instances
 from multiple threads. (Note that you aren't meant to create
 many FFI instances: in inline mode, you should write
 ffi = cffi.FFI() at module level just after import cffi, and in
 out-of-line mode you don't instantiate FFI explicitly at all.)
 * Windows: using callbacks can be messy because the CFFI internal
 error messages show up to stderr-but stderr goes nowhere in many
 applications. This makes it particularly hard to get started
 with the embedding mode. (Once you get started, you can at least
 use @ffi.def_extern(onerror=...) and send the error logs where
 it makes sense for your application, or record them in log
 files, and so on.) So what is new in CFFI is that now, on
 Windows CFFI will try to open a non-modal MessageBox (in addition
 to sending raw messages to stderr). The MessageBox is only
 visible if the process stays alive: typically, console
 applications that crash close immediately, but that is also the
 situation where stderr should be visible anyway.
 * Progress on support for callbacks in NetBSD.
 * Functions returning booleans ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'python-cffi, python-cryptography' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"python-cffi", rpm:"python-cffi~1.11.2~5.11.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-cryptography", rpm:"python-cryptography~2.1.4~7.28.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-xattr", rpm:"python-xattr~0.7.5~6.3.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cffi", rpm:"python3-cffi~1.11.2~5.11.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cryptography", rpm:"python3-cryptography~2.1.4~7.28.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"python-cffi", rpm:"python-cffi~1.11.2~5.11.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-cryptography", rpm:"python-cryptography~2.1.4~7.28.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-xattr", rpm:"python-xattr~0.7.5~6.3.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cffi", rpm:"python3-cffi~1.11.2~5.11.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cryptography", rpm:"python3-cryptography~2.1.4~7.28.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"python-cffi", rpm:"python-cffi~1.11.2~5.11.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-cryptography", rpm:"python-cryptography~2.1.4~7.28.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-xattr", rpm:"python-xattr~0.7.5~6.3.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cffi", rpm:"python3-cffi~1.11.2~5.11.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cryptography", rpm:"python3-cryptography~2.1.4~7.28.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"python-cffi", rpm:"python-cffi~1.11.2~5.11.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-cryptography", rpm:"python-cryptography~2.1.4~7.28.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-xattr", rpm:"python-xattr~0.7.5~6.3.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cffi", rpm:"python3-cffi~1.11.2~5.11.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cryptography", rpm:"python3-cryptography~2.1.4~7.28.2", rls:"SLES12.0SP5"))) {
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
