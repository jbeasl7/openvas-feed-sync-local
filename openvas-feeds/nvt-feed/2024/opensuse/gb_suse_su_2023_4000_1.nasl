# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833869");
  script_version("2025-03-12T05:38:19+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-12 05:38:19 +0000 (Wed, 12 Mar 2025)");
  script_tag(name:"creation_date", value:"2024-03-04 07:21:15 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for yq (SUSE-SU-2023:4000-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4000-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/POWEFXQTVVARSSFK4T2AMVB5ZX6HDSPP");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'yq'
  package(s) announced via the SUSE-SU-2023:4000-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for yq fixes the following issues:

  yq was updated to 4.35.2 (bsc#1215808):

  * Fixed number parsing as float bug in JSON #1756

  * Fixed string, null concatenation consistency #1712

  * Fixed expression parsing issue #1711

  Update to 4.35.1:

  * Added Lua output support

  * Added BSD checksum format

  Update to 4.34.1:

  * Added shell output format

  * Fixed nil pointer dereference

  Update to 4.33.3:

  * Fixed bug when splatting empty array #1613

  * Added scalar output for TOML (#1617)

  * Fixed passing of read-only context in pipe (partial fix for #1631)

  Update to 4.33.2:

  * Add `--nul-output-0` flag to separate element with NUL character (#1550)
      Thanks @vaab!

  * Add removable-media interface plug declaration to the snap packaging(#1618)
      Thanks @brlin-tw!

  * Scalar output now handled in csv, tsv and property files

  Update to 4.33.1:

  * Added read-only TOML support! #1364. Thanks @pelletier for making your API
      available in your toml lib :)

  * Added warning when auto detect by file type is outputs JSON

  Update to 4.32.2:

  * Fixes parsing terraform tfstate files results in 'unknown' format

  * Added divide and modulo operators (#1593)

  * Add support for decoding base64 strings without padding

  * Add filter operation (#1588) - thanks @rbren!

  * Detect input format based on file name extension (#1582)

  * Auto output format when input format is automatically detected

  * Fixed npe in log #1596

  * Improved binary file size!

  Update to 4.31.2:

  * Fixed merged anchor reference problem #1482

  * Fixed xml encoding of ProcInst #1563, improved XML comment handling

  * Allow build without json and xml support (#1556) Thanks

  Update to 4.31.1:

  * Added shuffle command #1503

  * Added ability to sort by multiple fields #1541

  * Added @sh encoder #1526

  * Added @uri/@urid encoder/decoder #1529

  * Fixed date comparison with string date #1537

  * Added from_unix/to_unix Operators");

  script_tag(name:"affected", value:"'yq' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"yq", rpm:"yq~4.35.2~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yq-debuginfo", rpm:"yq-debuginfo~4.35.2~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yq-bash-completion", rpm:"yq-bash-completion~4.35.2~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yq-fish-completion", rpm:"yq-fish-completion~4.35.2~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yq-zsh-completion", rpm:"yq-zsh-completion~4.35.2~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yq", rpm:"yq~4.35.2~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yq-debuginfo", rpm:"yq-debuginfo~4.35.2~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yq-bash-completion", rpm:"yq-bash-completion~4.35.2~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yq-fish-completion", rpm:"yq-fish-completion~4.35.2~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yq-zsh-completion", rpm:"yq-zsh-completion~4.35.2~150500.3.3.1", rls:"openSUSELeap15.5"))) {
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
