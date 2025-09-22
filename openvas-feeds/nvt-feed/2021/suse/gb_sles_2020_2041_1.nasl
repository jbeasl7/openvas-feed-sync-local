# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.2041.1");
  script_cve_id("CVE-2020-1967");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:59 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-30 15:06:14 +0000 (Thu, 30 Apr 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:2041-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:2041-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20202041-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rust, rust-cbindgen' package(s) announced via the SUSE-SU-2020:2041-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for rust, rust-cbindgen fixes the following issues:

rust was updated for use by Firefox 76ESR.

Fixed miscompilations with rustc 1.43 that lead to LTO failures
 (bsc#1173202)

Update to version 1.43.1

Updated openssl-src to 1.1.1g for CVE-2020-1967.

Fixed the stabilization of AVX-512 features.

Fixed `cargo package --list` not working with unpublished dependencies.

Update to version 1.43.0

Language:

Fixed using binary operations with `&{number}` (e.g. `&1.0`) not having
 the type inferred correctly.

Attributes such as `#[cfg()]` can now be used on `if` expressions.

Syntax only changes:
 * Allow `type Foo: Ord` syntactically.
 * Fuse associated and extern items up to defaultness.
 * Syntactically allow `self` in all `fn` contexts.
 * Merge `fn` syntax + cleanup item parsing.
 * `item` macro fragments can be interpolated into `trait`s, `impl`s, and
 `extern` blocks. For example, you may now write: ```rust macro_rules!
 mac_trait { ($i:item) => { trait T { $i } } } mac_trait! { fn foo() {}
 } ```
 * These are still rejected *semantically*, so you will likely receive an
 error but these changes can be seen and parsed by macros and
 conditional compilation.

Compiler

You can now pass multiple lint flags to rustc to override the previous
 flags.

 For example, `rustc -D unused -A unused-variables` denies everything in the `unused` lint group except `unused-variables` which is explicitly allowed. However, passing `rustc -A unused-variables -D unused` denies everything in the `unused` lint group **including** `unused-variables`
since the allow flag is specified before the deny flag (and therefore
 overridden).
rustc will now prefer your system MinGW libraries over its bundled
 libraries if they are available on `windows-gnu`.

rustc now buffers errors/warnings printed in JSON.

Libraries:

`Arc<[T, N]>`, `Box<[T, N]>`, and `Rc<[T, N]>`, now implement
 `TryFrom>`,`TryFrom>`, and `TryFrom>`
 respectively.
 **Note** These conversions are only available when `N` is `0..=32`.

You can now use associated constants on floats and integers directly,
 rather than having to import the module. e.g. You can now write
 `u32::MAX` or `f32::NAN` with no imports.

`u8::is_ascii` is now `const`.

`String` now implements `AsMut`.

Added the `primitive` module to `std` and `core`. This module reexports
 Rust's primitive types. This is mainly useful in macros where you want
 avoid these types being shadowed.

Relaxed some of the trait bounds on `HashMap` and `HashSet`.

`string::FromUtf8Error` now implements `Clone + Eq`.

Stabilized APIs

`Once::is_completed`

`f32::LOG10_2`

`f32::LOG2_10`

`f64::LOG10_2`

`f64::LOG2_10`

`iter::once_with`

Cargo

 - You can now set config `[profile]`s in your `.cargo/config`,
 or through your environment.
 - Cargo will now set `CARGO_BIN_EXE_` pointing to a binary's
 executable path when running integration tests or benchmarks. ``
 is the ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'rust, rust-cbindgen' package(s) on SUSE Linux Enterprise Module for Development Tools 15-SP1, SUSE Linux Enterprise Module for Development Tools 15-SP2.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"cargo", rpm:"cargo~1.43.1~12.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cargo-debuginfo", rpm:"cargo-debuginfo~1.43.1~12.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clippy", rpm:"clippy~1.43.1~12.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clippy-debuginfo", rpm:"clippy-debuginfo~1.43.1~12.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rls", rpm:"rls~1.43.1~12.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rls-debuginfo", rpm:"rls-debuginfo~1.43.1~12.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust", rpm:"rust~1.43.1~12.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-analysis", rpm:"rust-analysis~1.43.1~12.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-debuginfo", rpm:"rust-debuginfo~1.43.1~12.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-debugsource", rpm:"rust-debugsource~1.43.1~12.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-src", rpm:"rust-src~1.43.1~12.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-std-static", rpm:"rust-std-static~1.43.1~12.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rustfmt", rpm:"rustfmt~1.43.1~12.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rustfmt-debuginfo", rpm:"rustfmt-debuginfo~1.43.1~12.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"cargo", rpm:"cargo~1.43.1~12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cargo-debuginfo", rpm:"cargo-debuginfo~1.43.1~12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clippy", rpm:"clippy~1.43.1~12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clippy-debuginfo", rpm:"clippy-debuginfo~1.43.1~12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rls", rpm:"rls~1.43.1~12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rls-debuginfo", rpm:"rls-debuginfo~1.43.1~12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust", rpm:"rust~1.43.1~12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-analysis", rpm:"rust-analysis~1.43.1~12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-debuginfo", rpm:"rust-debuginfo~1.43.1~12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-debugsource", rpm:"rust-debugsource~1.43.1~12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-src", rpm:"rust-src~1.43.1~12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-std-static", rpm:"rust-std-static~1.43.1~12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rustfmt", rpm:"rustfmt~1.43.1~12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rustfmt-debuginfo", rpm:"rustfmt-debuginfo~1.43.1~12.1", rls:"SLES15.0SP2"))) {
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
