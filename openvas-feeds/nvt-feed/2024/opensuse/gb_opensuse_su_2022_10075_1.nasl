# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833413");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2021-32797");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-17 17:01:13 +0000 (Tue, 17 Aug 2021)");
  script_tag(name:"creation_date", value:"2024-03-04 07:22:55 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for python (openSUSE-SU-2022:10075-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:10075-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/VZGF2ZZFSQOBN7NRPXC3MMQXPLYLS2IH");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python'
  package(s) announced via the openSUSE-SU-2022:10075-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-jupyterlab fixes the following issues:
  Update to 2.2.10:

  * Remove `form` tags' `action` attribute during sanitizing, to prevent an
       XSS (CVE-2021-32797) (boo#1196663)

  * Header Content-Type should not be overwritten

  * Do not use token parameters in websocket urls

  * Properly handle errors in async browser_check

  * Cells can no longer be executed while kernels are terminating or
       restarting. There is a new status for these events on the Kernel
       Indicator

  * Add styling for high memory usage warning in status bar with nbresuse

  * Adds support for Python version 3.10

  * Support live editing of SVG with updating rendering

  * Lazy load codemirror theme stylesheets

  * Add feature request template + slight reorg in readme

  * Add link to react example in extension-examples repo

  * Close correct tab with close tab

  * Remove unused css rules

  * Simplified multicursor backspace code

  * Fix recent breaking changes to normalizepath in filebrowser

  * Handle quit_button when launched as an extension

  * Add worker-loader

  * Fix icon sidebar height for third party extensions

  * Scrolls cells into view after deletion

  * Support Node.js 10+

  * Select search text when focusing the search overlay

  * Throttle fetch requests in the setting registrys data connector

  * Avoid redundant checkpoint calls on loading a notebook");

  script_tag(name:"affected", value:"'python' package(s) on openSUSE Backports SLE-15-SP4.");

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

if(release == "openSUSEBackportsSLE-15-SP4") {

  if(!isnull(res = isrpmvuln(pkg:"jupyter-jupyterlab", rpm:"jupyter-jupyterlab~2.2.10~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-jupyterlab", rpm:"python3-jupyterlab~2.2.10~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jupyter-jupyterlab", rpm:"jupyter-jupyterlab~2.2.10~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-jupyterlab", rpm:"python3-jupyterlab~2.2.10~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
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