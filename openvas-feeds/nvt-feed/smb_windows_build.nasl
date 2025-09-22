# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description) {

  script_oid("1.3.6.1.4.1.25623.1.0.129001");
  script_version("2025-09-11T05:38:37+0000");
  script_tag(name:"last_modification", value:"2025-09-11 05:38:37 +0000 (Thu, 11 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-03-04 10:00:00 +0200 (Tue, 04 Mar 2025)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("SMB Windows Full Build Number");
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Windows");
  script_category(ACT_GATHER_INFO);
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"Gets the full build number of a Windows operating system using
  PowerShell via SMB.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("powershell_func.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if (!os_arch)
  exit(0);

# nb:
# - Does not work for OS older than Windows Server 2016 / Windows 10 per default as PS5.1 is missing
#   required
# - Get the full build number, e.g. 10.0.22000.1042
full_build_cmd = "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' -erroraction silentlycontinue | %{ $_.CurrentMajorVersionNumber,$_.CurrentMinorVersionNumber,$_.CurrentBuildNumber,$_.UBR }) -join '.'";
full_build = powershell_cmd(cmd:full_build_cmd);
if (!full_build || full_build !~ "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$")
  exit(0);

# nb: get os type, 1 = client, 2 = server, 3 = domain controller
os_type_cmd = "Get-CimInstance Win32_OperatingSystem -erroraction silentlycontinue | foreach-object {$_.producttype}";
os_type = powershell_cmd(cmd:os_type_cmd);
if (!os_type)
  exit(0);

set_kb_item(name:"Microsoft/Windows/Arch", value:os_arch);
set_kb_item(name:"Microsoft/Windows/FullBuild", value:full_build);

full_build_splitted = split(full_build, keep:FALSE, sep:".");
if (!full_build_splitted || max_index(full_build_splitted) != 4)
  exit(0);

if (full_build_splitted[0] != "10" || full_build_splitted[1] != "0")
  exit(0);

if (os_type == 1) {

  if (full_build_splitted[2] == "10240") {
    os_name = "Windows 10 Version 1507";

  } else if (full_build_splitted[2] == "10586") {
    os_name = "Windows 10 Version 1511";

  } else if (full_build_splitted[2] == "14393") {
    os_name = "Windows 10 Version 1607";

  } else if (full_build_splitted[2] == "15063") {
    os_name = "Windows 10 Version 1703";

  } else if (full_build_splitted[2] == "16299") {
    os_name = "Windows 10 Version 1709";

  } else if (full_build_splitted[2] == "17134") {
    os_name = "Windows 10 Version 1803";

  } else if (full_build_splitted[2] == "17763") {
    os_name = "Windows 10 Version 1809";

  } else if (full_build_splitted[2] == "18362") {
    os_name = "Windows 10 Version 1903";

  } else if (full_build_splitted[2] == "18363") {
    os_name = "Windows 10 Version 1909";

  } else if (full_build_splitted[2] == "19041") {
    os_name = "Windows 10 Version 2004";

  } else if (full_build_splitted[2] == "19042") {
    os_name = "Windows 10 Version 20H2";

  } else if (full_build_splitted[2] == "19043") {
    os_name = "Windows 10 Version 21H1";

  } else if (full_build_splitted[2] == "19044") {
    release_notus = "Windows 10";
    os_name = release_notus + " Version 21H2";

  } else if (full_build_splitted[2] == "19045") {
    release_notus = "Windows 10";
    os_name = release_notus + " Version 22H2";

  } else if (full_build_splitted[2] == "22000") {
    os_name = "Windows 11 Version 21H2";

  } else if (full_build_splitted[2] == "22621") {
    release_notus = "Windows 11";
    os_name = release_notus + " Version 22H2";

  } else if (full_build_splitted[2] == "22631") {
    release_notus = "Windows 11";
    os_name = release_notus + " Version 23H2";

  } else if (full_build_splitted[2] == "26100") {
    release_notus = "Windows 11";
    os_name = release_notus + " Version 24H2";

  } else {
    exit(0);
  }

} else if (os_type == "2" || os_type == "3") {

  if (full_build_splitted[2] == "14393") {
    release_notus = "Windows Server 2016";
    os_name = release_notus + " Version 1607";

  } else if (full_build_splitted[2] == "17763") {
    release_notus = "Windows Server 2019";
    os_name = release_notus + " Version 1809";

  } else if (full_build_splitted[2] == "18363") {
    os_name = "Windows Server Version 1909";

  } else if (full_build_splitted[2] == "19041") {
    os_name = "Windows Server Version 2004";

  } else if (full_build_splitted[2] == "19042") {
    os_name = "Windows Server Version 20H2";

  } else if (full_build_splitted[2] == "20348") {
    release_notus = "Windows Server 2022";
    os_name = release_notus + " Version 21H2";

  } else if (full_build_splitted[2] == "25398") {
    release_notus = "Windows Server 2022";
    os_name = "Windows Server Version 23H2";

  } else if (full_build_splitted[2] == "26100") {
    release_notus = "Windows Server 2025";
    os_name = release_notus;

  } else {
    exit(0);
  }

} else {
  exit(0);
}

# nb: Checks the Windows Server installation type, which can be "Server" or "Server Core"
if (os_type == "2" || os_type == "3") {
  install_type = powershell_cmd(cmd:"(Get-ComputerInfo -erroraction silentlycontinue).WindowsInstallationType");
  if (!install_type || install_type !~ "^(Server|Server Core)$" ) {
    log_message(data:"Could not get Windows Server installation type", port:0);
    exit(0);
  }
  set_kb_item(name:"Microsoft/Windows/Server/InstallType", value:install_type);

  if (install_type == "Server Core")
    os_name += " (Server Core installation)";
}

os_name += " " + os_arch;

set_kb_item(name:"ssh/login/release_notus", value:release_notus);
set_kb_item(name:"ssh/login/package_list_notus", value:os_name + ";" + full_build);
set_kb_item(name:"Microsoft/Windows/FullName", value:os_name);

exit(0);
