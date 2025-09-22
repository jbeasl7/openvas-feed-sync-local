# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.887130");
  script_version("2025-04-24T05:40:01+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-24 05:40:01 +0000 (Thu, 24 Apr 2025)");
  script_tag(name:"creation_date", value:"2024-06-07 06:36:05 +0000 (Fri, 07 Jun 2024)");
  script_name("Fedora: Security Advisory for rust-python-launcher (FEDORA-2024-40ee18b2e7)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-40ee18b2e7");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LBLY2BG4YULR3TN7RT7P4BSSY6H6DIYT");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rust-python-launcher'
  package(s) announced via the FEDORA-2024-40ee18b2e7 advisory.
Note: This VT has been deprecated as a duplicate.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Python Launcher for Unix.

Launch your Python interpreter the lazy/smart way!

This launcher is an implementation of the py command for Unix-based platforms.

The goal is to have py become the cross-platform command that Python users
typically use to launch an interpreter while doing development.
By having a command that is version-agnostic when it comes to Python,
it side-steps the 'what should the python command point to?' debate by clearly
specifying that upfront (i.e. the newest version of Python that can be found).
This also unifies the suggested command to document for launching Python on
both Windows as Unix as py has existed as the preferred command on Windows
since 2012 with the release of Python 3.3.

Typical usage would be:

    py -m venv .venv
    py ...  # Whatever you would normally use `python` for during development.

This creates a virtual environment in a .venv directory using the latest
version of Python installed. Subsequent uses of py will then use that virtual
environment as long as it is in the current (or higher) directory,
no environment activation required (although the Python Launcher supports
activated environments as well)!

A non-goal of this launcher is to become the way to launch the Python
interpreter all the time. If you know the exact interpreter you want to
launch then you should launch it directly, same goes for when you have
requirements on the type of interpreter you want.
The Python Launcher should be viewed as a tool of convenience, not necessity.");

  script_tag(name:"affected", value:"'rust-python-launcher' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
