# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.85681029991005101");
  script_cve_id("CVE-2024-53899");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-10 18:12:06 +0000 (Mon, 10 Feb 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2024-8568f9cd5e)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-8568f9cd5e");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-8568f9cd5e");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2327512");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2328746");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2329188");
  script_xref(name:"URL", value:"https://docs.astral.sh/uv/configuration/files/");
  script_xref(name:"URL", value:"https://github.com/astral-sh/uv/issues/9424");
  script_xref(name:"URL", value:"https://github.com/astral-sh/uv/releases/tag/0.5.0");
  script_xref(name:"URL", value:"https://github.com/astral-sh/uv/releases/tag/0.5.1");
  script_xref(name:"URL", value:"https://github.com/astral-sh/uv/releases/tag/0.5.2");
  script_xref(name:"URL", value:"https://github.com/astral-sh/uv/releases/tag/0.5.3");
  script_xref(name:"URL", value:"https://github.com/astral-sh/uv/releases/tag/0.5.4");
  script_xref(name:"URL", value:"https://github.com/astral-sh/uv/releases/tag/0.5.5");
  script_xref(name:"URL", value:"https://pypi.org/project/virtualenv/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'uv' package(s) announced via the FEDORA-2024-8568f9cd5e advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update `uv` from 0.4.30 to 0.5.5. This is a significant update. Please see the following notes.

----

By updating to a current release of `uv`, this update fixes [CVE-2024-53899]([link moved to references]), which was originally reported against [`virtualenv`]([link moved to references]) but which was also reproducible on `uv` 0.5.2 and earlier. See [upstream issue #9424]([link moved to references]) for more details.

----

This update adds a default system-wide configuration file `/etc/uv/uv.toml` with settings specific to Fedora. The RPM-packaged `uv` now deviates from the default configuration in two ways.

First, we set `'python-downloads'` to `'manual'` in order to avoid unintended Python downloads. We suggest using RPM-packaged (system) Pythons that benefit from distribution maintenance and integration. Use `uv python install` to manually install managed Pythons.

Second, we set `'python-preference'` to `'system'` instead of `'managed'`. Otherwise, any managed Python would be used for `uv` operations where no particular Python is specified, even if the only available managed Python were much older than the primary system Python.

No choices can be appropriate for all users and applications. To restore the default behavior, comment out settings in this file or override them in a configuration file with higher precedence, such as a user-level configuration file. See [link moved to references] for details on the interaction of project-, user-, and system-level configuration files.

----

With 0.5.0, `uv` introduced several potentially breaking changes. The developers write that these are 'changes that improve correctness and user experience, but could break some workflows. This release contains those changes, many have been marked as breaking out of an abundance of caution. We expect most users to be able to upgrade without making changes.'

- Use base executable to set virtualenv Python path
- Use XDG (i.e. `~/.local/bin`) instead of the Cargo home directory in the installer
- Discover and respect .python-version files in parent directories
- Error when disallowed settings are defined in `uv.toml`
- Implement PEP 440-compliant local version semantics
- Treat the base Conda environment as a system environment
- Do not allow pre-releases when the `!=` operator is used
- Prefer `USERPROFILE` over `FOLDERID_Profile` when selecting a home directory on Windows
- Improve interactions between color environment variables and CLI options
- Make `allow-insecure-host` a global option
- Only write `.python-version` files during `uv init` for workspace members if the version differs

For detailed discussion of these changes, please see [link moved to references].

For other fixes, enhancements, and changes in this update, please consult the following:

- [links moved to references]");

  script_tag(name:"affected", value:"'uv' package(s) on Fedora 41.");

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

if(release == "FC41") {

  if(!isnull(res = isrpmvuln(pkg:"python3-uv", rpm:"python3-uv~0.5.5~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uv", rpm:"uv~0.5.5~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uv-debuginfo", rpm:"uv-debuginfo~0.5.5~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uv-debugsource", rpm:"uv-debugsource~0.5.5~2.fc41", rls:"FC41"))) {
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
